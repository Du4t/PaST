#!/usr/bin/env python3
"""
FTFuzz Online State-Transition Monitor

Watches the AFL++ queue directory during fuzzing and incrementally consumes
newly generated .ftstate.json sidecar files. Maintains in-memory online state
and exports versioned online_*.json artifacts for runtime control-plane consumption.

Usage:
  # Daemon mode
  python3 monitor/online_state_monitor.py \\
      --queue-dir /tmp/ftfuzz_out/default/queue \\
      --out-dir /tmp/ftfuzz_online \\
      --state-map /tmp/ftfuzz_dgf/libxml2/state_map.csv \\
      --source-root /path/to/source \\
      --interval 1.0 \\
      --daemon

  # One-shot mode
  python3 monitor/online_state_monitor.py \\
      --queue-dir /tmp/ftfuzz_out/default/queue \\
      --out-dir /tmp/ftfuzz_online \\
      --state-map /tmp/ftfuzz_dgf/libxml2/state_map.csv \\
      --once
"""

import argparse
import csv
import json
import os
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone

# Add project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from monitor.state_classes import (
    classify_transition, normalize_state_class, state_class_rank,
    CANONICAL_CLASSES, CLASS_RANK,
)
from tools.source_context import (
    extract_combined_snippet, get_barrier_condition_placeholder,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCHEMA_STSR = "ftfuzz.online_stsr.v1"
SCHEMA_RANKING = "ftfuzz.online_barrier_ranking.v1"
SCHEMA_BUCKETS = "ftfuzz.online_seed_buckets.v1"
SCHEMA_CONTEXT = "ftfuzz.online_transition_runtime_context.v1"
SCHEMA_STATUS = "ftfuzz.online_monitor_status.v1"

DEFAULT_BARRIER_WEIGHTS = {
    'w_pre': 0.2,
    'w_barrier': 1.0,
    'w_blocked': 1.5,
    'w_low_stsr': 2.0,
    'w_recent': 0.5,
    'w_post': 0.8,
}


# ---------------------------------------------------------------------------
# Utility: atomic JSON writer
# ---------------------------------------------------------------------------
def atomic_write_json(path, data):
    """Write JSON atomically: write to temp then rename."""
    dirname = os.path.dirname(path)
    tmp_path = path + '.tmp'
    try:
        with open(tmp_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# State map loader
# ---------------------------------------------------------------------------
def load_state_map(path):
    """Load state_map.csv into per-transition metadata.

    Returns dict: transition_id -> {pre_state, barrier, post_state, sources, source}
    """
    transitions = defaultdict(lambda: {
        'pre_state': {}, 'barrier': {}, 'post_state': {},
        'sources': set(),
    })
    if not path or not os.path.exists(path):
        return dict(transitions)

    try:
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                tid = row.get('transition_id', '').strip()
                role = row.get('role', '').strip().lower()
                source = row.get('source', '').strip()

                if role in ('pre', 'pre_state'):
                    key = 'pre_state'
                elif role == 'barrier':
                    key = 'barrier'
                elif role in ('post', 'post_state'):
                    key = 'post_state'
                else:
                    continue

                transitions[tid][key] = {
                    'file': row.get('file', '').strip(),
                    'line': int(row['line']) if row.get('line', '').strip().lstrip('-').isdigit() else 0,
                    'function': row.get('function', '').strip(),
                    'bb_id': int(row['bb_id']) if row.get('bb_id', '').strip().lstrip('-').isdigit() else -1,
                    'state_id': int(row['state_id']) if row.get('state_id', '').strip().isdigit() else -1,
                }
                if source:
                    transitions[tid]['sources'].add(source)
    except Exception:
        pass

    # Resolve source label + build state_id -> tid reverse map
    result = {}
    state_to_tid = {}  # state_id (int) -> transition_id (str)
    for tid, t in transitions.items():
        sources = t.pop('sources', set())
        if 'manual' in sources:
            source_label = 'manual'
        elif 'auto-generated' in sources:
            source_label = 'auto-generated'
        elif sources:
            source_label = sorted(sources)[0]
        else:
            source_label = 'unspecified'
        t['source'] = source_label
        result[tid] = t

        # Build reverse mapping
        for role_key in ('pre_state', 'barrier', 'post_state'):
            sid = t[role_key].get('state_id')
            if sid is not None and sid >= 0:
                state_to_tid[sid] = tid

    result['_state_to_tid'] = state_to_tid
    return result


# ---------------------------------------------------------------------------
# Sidecar discovery
# ---------------------------------------------------------------------------
class SidecarIndex:
    """Tracks processed sidecar files to avoid re-processing."""

    def __init__(self):
        self._processed = {}  # path -> (mtime, size)

    def is_new_or_changed(self, path):
        """Return True if the sidecar is new or has changed since last seen."""
        try:
            st = os.stat(path)
            key = (st.st_mtime, st.st_size)
        except OSError:
            return False

        last = self._processed.get(path)
        if last is None or last != key:
            self._processed[path] = key
            return True
        return False

    @property
    def processed_count(self):
        return len(self._processed)


def discover_sidecars(queue_dir, index):
    """Discover new or changed .ftstate.json sidecar files.

    Returns list of (path, data) tuples for newly discovered files.
    Handles partially written files gracefully.
    """
    new_files = []
    try:
        entries = os.listdir(queue_dir)
    except OSError:
        return new_files

    for fname in entries:
        if not fname.endswith('.ftstate.json'):
            continue
        fpath = os.path.join(queue_dir, fname)

        if not index.is_new_or_changed(fpath):
            continue

        # Attempt to load; retry later if parse fails (partial write)
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)
            new_files.append((fpath, data))
        except (IOError, json.JSONDecodeError):
            # Partial write or corrupt - skip, will retry next scan
            pass

    return new_files


# ---------------------------------------------------------------------------
# Incremental statistics
# ---------------------------------------------------------------------------
class OnlineStats:
    """Incrementally maintained per-transition runtime statistics."""

    def __init__(self):
        self.pre_count = defaultdict(int)
        self.barrier_count = defaultdict(int)
        self.post_count = defaultdict(int)
        self.blocked_count = defaultdict(int)
        self.invalid_post_without_pre = defaultdict(int)
        self.class_distribution = defaultdict(lambda: defaultdict(int))
        # Seed buckets: tid -> class -> list of seed entries
        self.seed_buckets = defaultdict(lambda: defaultdict(list))
        self.total_sidecars = 0
        self.parse_errors = 0
        self._recent_activity = defaultdict(float)  # tid -> last activity timestamp

    def ingest(self, sidecar_data, state_to_tid=None):
        """Ingest a single .ftstate.json sidecar file.

        Sidecar transitions dict uses state_id (int) as keys.
        Multiple state_ids may belong to the same transition_id (e.g. pre/barrier/post).
        We aggregate per-transition for the seed, then classify.
        """
        transitions = sidecar_data.get('transitions', {})
        seed_path = sidecar_data.get('seed', '')
        min_distance = sidecar_data.get('min_distance', 0)
        reached_target = sidecar_data.get('reached_target', False)
        sidecar_path = sidecar_data.get('_sidecar_path', '')

        # Seed timestamp
        seed_mtime = time.time()
        if sidecar_path:
            try:
                seed_mtime = os.stat(sidecar_path).st_mtime
            except OSError:
                pass

        now = time.time()
        state_to_tid = state_to_tid or {}

        # First pass: aggregate per-transition booleans across state_ids
        tid_aggregates = defaultdict(lambda: {'pre': False, 'bar': False, 'post': False,
                                               'target_taken': False, 'non_target_taken': False,
                                               'bar_count': 0, 'target_count': 0, 'non_target_count': 0})

        for state_key, tdata in transitions.items():
            try:
                sid = int(state_key)
            except (ValueError, TypeError):
                sid = -1

            tid = state_to_tid.get(sid, state_key)
            agg = tid_aggregates[tid]

            # New format: barrier-only (Stage 2.3-fix)
            bar_hit = tdata.get('barrier_hit', False)
            target_count = tdata.get('target_edge_taken_count', 0)
            non_target_count = tdata.get('non_target_edge_taken_count', 0)
            bar_count = tdata.get('barrier_hit_count', 0)
            # Legacy compat
            pre_hit = tdata.get('pre_hit', False)
            post_hit = tdata.get('post_hit', False)

            if pre_hit: agg['pre'] = True
            if bar_hit or bar_count > 0: agg['bar'] = True
            if post_hit: agg['post'] = True
            if target_count > 0: agg['target_taken'] = True
            if non_target_count > 0: agg['non_target_taken'] = True
            agg['bar_count'] += bar_count
            agg['target_count'] += target_count
            agg['non_target_count'] += non_target_count

        # Second pass: classify each transition and update stats
        min_dist = sidecar_data.get('min_distance', 999)
        for tid, agg in tid_aggregates.items():
            pre = agg['pre']
            bar = agg['bar']
            post = agg['post']
            target_taken = agg.get('target_taken', False)
            # "post" equivalent: barrier was hit AND target direction was taken
            effective_post = post or target_taken
            cls = classify_transition(pre or bar, bar, effective_post)

            if pre or bar:
                self.pre_count[tid] += 1
            if bar:
                self.barrier_count[tid] += 1
            if effective_post:
                self.post_count[tid] += 1
            if bar and not effective_post:
                self.blocked_count[tid] += 1
            if not (pre or bar) and effective_post:
                self.invalid_post_without_pre[tid] += 1

            self.class_distribution[tid][cls] += 1
            self._recent_activity[tid] = now

            # Seed bucket entry
            self.seed_buckets[tid][cls].append({
                'seed_path': seed_path,
                'sidecar_path': sidecar_path,
                'min_distance': min_distance,
                'reached_target': reached_target,
                'class': cls,
                'timestamp_unix_ms': int(seed_mtime * 1000),
            })

        self.total_sidecars += 1

    def get_stsr(self, tid):
        pre = self.pre_count[tid]
        if pre == 0:
            return 0.0
        return self.post_count[tid] / pre

    def get_barrier_pass_rate(self, tid):
        bar = self.barrier_count[tid]
        if bar == 0:
            return 0.0
        return self.post_count[tid] / bar

    def all_tids(self):
        """Return all known transition IDs."""
        tids = set()
        tids.update(self.pre_count.keys())
        tids.update(self.barrier_count.keys())
        tids.update(self.post_count.keys())
        return sorted(tids)

    def get_state_distribution(self, tid):
        dist = {}
        for cls in CANONICAL_CLASSES:
            dist[cls] = self.class_distribution[tid].get(cls, 0)
        return dist

    def get_top_k_seeds(self, tid, top_k=50):
        """Get top-k seeds per state class for a transition.

        Selection heuristic:
          Barrier-Reached > Reach-Pre > Reach-Post > Fail-Pre > Invalid
          Smaller min_distance is better
          Newer seeds get slight priority
        """
        result = {}
        for cls in CANONICAL_CLASSES:
            seeds = self.seed_buckets[tid].get(cls, [])
            if not seeds:
                result[cls] = []
                continue

            def sort_key(s):
                dist = s.get('min_distance', 0xFFFFFFFF)
                ts = s.get('timestamp_unix_ms', 0)
                # Lower distance = better, newer = slightly better
                return (dist, -ts)

            sorted_seeds = sorted(seeds, key=sort_key)
            result[cls] = sorted_seeds[:top_k]

        return result


# ---------------------------------------------------------------------------
# Barrier ranking
# ---------------------------------------------------------------------------
def compute_barrier_ranking(stats, candidate_transitions=None):
    """Frontier-aware barrier ranking (Stage 2.3-fix enhanced).

    Identifies the fuzzer's current distance frontier and ranks barriers
    accordingly. Only barriers at the frontier (closest reached distance to
    target) are candidates for active intervention (field inference, LLM,
    policy generation). Barriers behind the frontier are monitored but
    deprioritized.

    Frontier definition:
      frontier_distance = min{ barrier.pre_state.distance | barrier_hit_count > 0 }

    Tier system:
      frontier_active:    at frontier, blocked — needs intervention NOW
      frontier_passing:   at frontier, not blocked — making progress
      unreached_frontier: closer than frontier, not reached — exploration target
      behind_frontier:    further than frontier, reached — monitor only
      distant:            far away, unreached — ignore
    """
    tids = set(stats.all_tids())
    if not tids: return []

    # Build per-transition distance maps from candidate transitions
    tid_pre_distance = {}   # tid -> pre_state distance (barrier BB distance)
    tid_post_distance = {}  # tid -> post_state distance (after crossing)
    if candidate_transitions:
        for t in candidate_transitions.get('transitions', []):
            tid = t.get('transition_id', '')
            post_dist = t.get('post_state', {}).get('distance', float('inf'))
            pre_dist = t.get('pre_state', {}).get('distance', float('inf'))
            if post_dist > 0 and post_dist < float('inf'):
                tid_post_distance[tid] = post_dist
            if pre_dist > 0 and pre_dist < float('inf'):
                tid_pre_distance[tid] = pre_dist

    # Include close transitions even if unreached by sidecar
    for tid, dist in list(tid_post_distance.items()):
        if tid not in tids and dist < 100:
            tids.add(tid)

    if not tids: return []

    import math
    DIST_LAMBDA = 5.0       # exponential decay constant for distance scoring
    FRONTIER_WINDOW = 3.0   # tolerance for "at frontier" (pre_dist diff)

    # ---- Step 1: Compute frontier distance ----
    # frontier = minimum pre_state distance among all REACHED barriers
    frontier_dist = float('inf')
    for tid in tids:
        pre_dist = tid_pre_distance.get(tid, float('inf'))
        bar = (stats.barrier_count.get(tid, 0) if hasattr(stats, 'barrier_count')
               else stats.pre_count.get(tid, 0))
        if bar > 0 and pre_dist < frontier_dist:
            frontier_dist = pre_dist

    # Fallback: if no barrier was ever reached, use minimum pre_dist among all
    if frontier_dist == float('inf'):
        all_pre = [d for d in tid_pre_distance.values() if d < float('inf')]
        frontier_dist = min(all_pre) if all_pre else 0.0

    # ---- Step 2: Score and classify each barrier ----
    ranked = []

    for tid in tids:
        pre_dist = tid_pre_distance.get(tid, 999.0)
        post_dist = tid_post_distance.get(tid, 999.0)
        bar = (stats.barrier_count.get(tid, 0) if hasattr(stats, 'barrier_count')
               else stats.pre_count.get(tid, 0))
        post = stats.post_count.get(tid, 0) if hasattr(stats, 'post_count') else 0
        blocked = stats.blocked_count.get(tid, 0) if hasattr(stats, 'blocked_count') else max(0, bar - post)

        # Base distance score (post_dist: how close after crossing)
        dist_score = math.exp(-post_dist / DIST_LAMBDA)

        # Evidence score
        direction_bonus = min(1.0, post / max(bar, 1)) if bar > 0 else 0
        evidence_score = 0.5 * min(1.0, bar / 100.0) + 0.5 * direction_bonus

        # Base quality score: 80% distance, 20% runtime evidence
        base_score = 0.80 * dist_score + 0.20 * evidence_score

        # ---- Step 3: Frontier analysis and tier classification ----
        dist_to_frontier = pre_dist - frontier_dist
        is_reached = bar > 0
        is_blocked = blocked > 0  # has seeds stuck at this barrier

        if is_reached and dist_to_frontier <= FRONTIER_WINDOW:
            # At the frontier — this barrier IS the current obstacle
            if is_blocked:
                tier = 'frontier_active'
                multiplier = 1.8
                action = 'active_obstacle'
                reason = (f'FRONTIER OBSTACLE: barrier at dist={pre_dist:.1f}, '
                          f'{blocked} seeds blocked, needs field inference')
            else:
                tier = 'frontier_passing'
                multiplier = 1.0
                action = 'frontier_passing'
                reason = (f'Frontier barrier passing (dist={pre_dist:.1f}, '
                          f'bar={bar}, post={post})')
        elif is_reached and dist_to_frontier > FRONTIER_WINDOW:
            # Behind frontier — already passed; not the immediate obstacle
            tier = 'behind_frontier'
            multiplier = 0.2
            action = 'monitor'
            reason = (f'Behind frontier (dist={pre_dist:.1f} > '
                      f'frontier={frontier_dist:.1f}), monitor only')
        elif not is_reached and pre_dist < frontier_dist - FRONTIER_WINDOW:
            # Closer to target than any reached barrier — exploration priority
            tier = 'unreached_frontier'
            multiplier = 1.2
            action = 'explore'
            reason = (f'Unreached frontier target (dist={pre_dist:.1f}), '
                      f'closer than current frontier ({frontier_dist:.1f})')
        elif not is_reached and pre_dist <= frontier_dist + FRONTIER_WINDOW:
            # Near the frontier but not reached — moderate exploration priority
            tier = 'near_frontier'
            multiplier = 0.6
            action = 'explore'
            reason = (f'Near-frontier target (dist={pre_dist:.1f}), '
                      f'needs exploration')
        else:
            # Distant and unreached — lowest priority
            tier = 'distant'
            multiplier = 0.1
            action = 'monitor'
            reason = f'Distant unreached barrier (dist={pre_dist:.1f})'

        final_score = base_score * multiplier

        # Blocked bonus only for frontier_active barriers
        if is_blocked and tier == 'frontier_active':
            final_score += 0.15

        ranked.append({
            'transition_id': tid,
            'score': round(final_score, 4),
            'distance_to_target': round(post_dist, 1),
            'pre_state_distance': round(pre_dist, 1),
            'post_state_distance': round(post_dist, 1),
            'frontier_distance': round(frontier_dist, 1),
            'distance_to_frontier': round(dist_to_frontier, 1),
            'tier': tier,
            'distance_score': round(dist_score, 4),
            'evidence_score': round(evidence_score, 4),
            'pre_count': bar, 'barrier_count': bar, 'post_count': post,
            'blocked_count': blocked, 'stsr': round(direction_bonus, 4),
            'recommended_action': action, 'reason': reason,
        })

    ranked.sort(key=lambda x: x['score'], reverse=True)
    for i, r in enumerate(ranked):
        r['rank'] = i + 1
    return ranked
# ---------------------------------------------------------------------------
# Online output builders
# ---------------------------------------------------------------------------
def build_online_stsr(stats, version, state_map):
    """Build online_stsr.json content."""
    tids = set(stats.all_tids())
    transitions = {}
    for tid in tids:
        transitions[tid] = {
            'pre_count': stats.pre_count[tid],
            'barrier_count': stats.barrier_count[tid],
            'post_count': stats.post_count[tid],
            'invalid_post_without_pre_count': stats.invalid_post_without_pre.get(tid, 0),
            'stsr': round(stats.get_stsr(tid), 6),
            'barrier_pass_rate': round(stats.get_barrier_pass_rate(tid), 6),
            'state_distribution': stats.get_state_distribution(tid),
        }

    return {
        'schema_version': SCHEMA_STSR,
        'version': version,
        'updated_at_unix_ms': int(time.time() * 1000),
        'processed_sidecars': stats.total_sidecars,
        'transitions': transitions,
    }


def build_online_barrier_ranking(stats, version, weights=None, candidate_transitions=None):
    """Build online_barrier_ranking.json content with distance-based ranking."""
    ranked = compute_barrier_ranking(stats, candidate_transitions=candidate_transitions)
    active = ranked[0]['transition_id'] if ranked else None

    return {
        'schema_version': SCHEMA_RANKING,
        'version': version,
        'updated_at_unix_ms': int(time.time() * 1000),
        'processed_sidecars': stats.total_sidecars,
        'active_transition': active,
        'ranked_transitions': ranked,
    }


def build_online_seed_buckets(stats, version, top_k=50):
    """Build online_seed_buckets.json content."""
    tids = set(stats.all_tids())
    transitions = {}
    for tid in tids:
        buckets = stats.get_top_k_seeds(tid, top_k)
        transitions[tid] = buckets

    return {
        'schema_version': SCHEMA_BUCKETS,
        'version': version,
        'updated_at_unix_ms': int(time.time() * 1000),
        'processed_sidecars': stats.total_sidecars,
        'top_k': top_k,
        'transitions': transitions,
    }


def _get_barrier_condition(tid, candidate_transitions):
    """Get enriched barrier condition from candidate transitions data.

    Accepts either a tid-keyed dict (from OnlineMonitor._load_candidate_transitions)
    or a raw dict with 'transitions' list. Returns the condition dict if
    available, falling back to the placeholder stub if not found.
    """
    if candidate_transitions:
        # Tid-keyed dict format (from OnlineMonitor)
        if tid in candidate_transitions:
            ct = candidate_transitions[tid]
            if isinstance(ct, dict):
                cond = ct.get('condition')
                if cond and cond.get('available') and cond.get('lhs') is not None:
                    return cond
        # Raw format with 'transitions' list
        for c in candidate_transitions.get('transitions', []):
            if c.get('transition_id') == tid:
                cond = c.get('barrier', {}).get('condition', {})
                if cond.get('available') and cond.get('lhs') is not None:
                    return {
                        'available': True,
                        'kind': cond.get('kind', 'unknown'),
                        'predicate': cond.get('predicate'),
                        'lhs': cond.get('lhs'),
                        'rhs': cond.get('rhs'),
                    }
                break
    return get_barrier_condition_placeholder()


def build_online_transition_runtime_context(stats, version, state_map, source_root, top_k=50,
                                             state_semantics=None, candidate_transitions=None):
    """Build online_transition_runtime_context.json content."""
    tids = set(stats.all_tids())
    ranked = compute_barrier_ranking(stats, candidate_transitions=candidate_transitions)
    ranked_map = {r['transition_id']: r for r in ranked}

    active_tid = ranked[0]['transition_id'] if ranked else None

    # Pre-load semantic entries
    semantic_entries = {}
    if state_semantics and 'transitions' in state_semantics:
        semantic_entries = state_semantics['transitions']

    transitions = {}
    for tid in tids:
        sm = state_map.get(tid, {})
        pre_loc = sm.get('pre_state', {})
        bar_loc = sm.get('barrier', {})
        post_loc = sm.get('post_state', {})

        # Source context
        locations = {
            'pre_state': pre_loc if pre_loc else {'file': None, 'line': 0},
            'barrier': bar_loc if bar_loc else {'file': None, 'line': 0},
            'post_state': post_loc if post_loc else {'file': None, 'line': 0},
        }
        src_ctx = {}
        if source_root:
            src_ctx = extract_combined_snippet(source_root, locations)

        # Field inference readiness
        pre = stats.pre_count[tid]
        bar = stats.barrier_count[tid]
        post = stats.post_count[tid]
        blocked = stats.blocked_count[tid]

        field_ready = False
        field_reason = 'unreached_transition'
        if pre == 0:
            field_reason = 'unreached_transition'
        elif post > 0 and blocked == 0:
            field_reason = 'already_passed_transition'
        elif blocked < 3:
            field_reason = 'not_enough_barrier_reached_seeds'
        elif pre < 10:
            field_reason = 'not_enough_reach_pre_seeds'
        else:
            field_ready = True
            field_reason = 'has enough Reach-Pre and Barrier-Reached seeds'

        # Seed buckets summary
        seed_buckets = {}
        topk = stats.get_top_k_seeds(tid, top_k)
        for cls in CANONICAL_CLASSES:
            seed_buckets[cls] = [
                {'seed_path': s['seed_path'], 'min_distance': s['min_distance']}
                for s in topk.get(cls, [])[:5]
            ]

        rinfo = ranked_map.get(tid, {})

        transitions[tid] = {
            'transition_id': tid,
            'source': sm.get('source', 'unspecified'),
            'pre_state': {
                'file': pre_loc.get('file'),
                'line': pre_loc.get('line', 0),
                'function': pre_loc.get('function'),
                'snippet': {
                    'available': src_ctx.get('available', False),
                    'text': src_ctx.get('pre_snippet'),
                } if src_ctx else {'available': False, 'text': None},
            },
            'barrier': {
                'file': bar_loc.get('file'),
                'line': bar_loc.get('line', 0),
                'function': bar_loc.get('function'),
                'condition': _get_barrier_condition(tid, candidate_transitions),
                'snippet': {
                    'available': src_ctx.get('available', False),
                    'text': src_ctx.get('barrier_snippet'),
                } if src_ctx else {'available': False, 'text': None},
            },
            'post_state': {
                'file': post_loc.get('file'),
                'line': post_loc.get('line', 0),
                'function': post_loc.get('function'),
                'snippet': {
                    'available': src_ctx.get('available', False),
                    'text': src_ctx.get('post_snippet'),
                } if src_ctx else {'available': False, 'text': None},
            },
            'branch_direction': _get_branch_direction(tid, candidate_transitions),
            'online_stats': {
                'pre_count': pre,
                'barrier_count': bar,
                'post_count': post,
                'stsr': round(stats.get_stsr(tid), 4),
                'barrier_pass_rate': round(stats.get_barrier_pass_rate(tid), 4),
            },
            'seed_buckets': seed_buckets,
            'field_inference_readiness': {
                'ready': field_ready,
                'reason': field_reason,
                'min_required_reach_pre': 10,
                'min_required_barrier_reached': 3,
            },
            'llm_placeholder': {
                'enabled': False,
                'reserved_interface': True,
            },
            'semantics': _get_semantics_for_tid(tid, semantic_entries),
        }

    return {
        'schema_version': SCHEMA_CONTEXT,
        'version': version,
        'updated_at_unix_ms': int(time.time() * 1000),
        'processed_sidecars': stats.total_sidecars,
        'active_transition': active_tid,
        'transitions': transitions,
    }


def _get_branch_direction(tid, candidate_transitions):
    """Extract branch direction metadata for a transition."""
    if not candidate_transitions or tid not in candidate_transitions:
        return {'available': False}
    ct = candidate_transitions[tid]
    return {
        'available': True,
        'desired_outcome': ct.get('desired_outcome'),
        'direction_source': ct.get('direction_source', 'unknown'),
        'true_successor_bb': ct.get('true_successor_bb'),
        'false_successor_bb': ct.get('false_successor_bb'),
        'distance_true': ct.get('distance_true'),
        'distance_false': ct.get('distance_false'),
        'barrier_type': ct.get('barrier_type', ''),
    }


def _get_semantics_for_tid(tid, semantic_entries):
    """Return semantics section for a transition, or {'available': False}."""
    if not semantic_entries:
        return {'available': False}
    entry = semantic_entries.get(tid)
    if not entry:
        return {'available': False}
    return {
        'available': True,
        'pre_state_summary': entry.get('pre_state_summary', {}),
        'barrier_summary': entry.get('barrier_summary', {}),
        'post_state_summary': entry.get('post_state_summary', {}),
        'transition_constraints': entry.get('transition_constraints', {}),
        'confidence': entry.get('confidence', 0.0),
        'llm_status': entry.get('llm_status', 'unknown'),
    }


def build_online_monitor_status(stats, version, queue_dir, out_dir,
                                 last_scan_ms, errors_list):
    """Build online_monitor_status.json content."""
    return {
        'schema_version': SCHEMA_STATUS,
        'version': version,
        'updated_at_unix_ms': int(time.time() * 1000),
        'running': True,
        'queue_dir': queue_dir,
        'out_dir': out_dir,
        'processed_sidecars': stats.total_sidecars,
        'parse_errors': stats.parse_errors,
        'last_scan_duration_ms': last_scan_ms,
        'warnings': errors_list[-10:] if errors_list else [],
    }


# ---------------------------------------------------------------------------
# Main monitor loop
# ---------------------------------------------------------------------------
class OnlineMonitor:
    """Online state-transition monitor daemon."""

    def __init__(self, queue_dir, out_dir, state_map_path, source_root=None,
                 interval=1.0, top_k=50, verbose=False, state_semantics_path=None,
                 candidate_transitions_path=None):
        self.queue_dir = queue_dir
        self.out_dir = out_dir
        self.state_map_path = state_map_path
        self.source_root = source_root
        self.interval = interval
        self.top_k = top_k
        self.verbose = verbose
        self.state_semantics_path = state_semantics_path
        self.candidate_transitions_path = candidate_transitions_path

        self.stats = OnlineStats()
        self.index = SidecarIndex()
        self.state_map = {}
        self.state_semantics = {}
        self.candidate_transitions = {}  # tid -> branch direction data
        self.candidate_transitions_raw = {}  # full JSON for distance data
        self.version = 0
        self.errors_log = []

        os.makedirs(out_dir, exist_ok=True)

        # Load state semantics if provided
        if state_semantics_path:
            self._load_semantics()

        # Load candidate transitions for branch direction metadata
        if candidate_transitions_path:
            self._load_candidate_transitions()

    def reload_state_map(self):
        self.state_map = load_state_map(self.state_map_path)

    def _load_candidate_transitions(self):
        """Load candidate_transitions.refined.json for branch direction metadata."""
        if not self.candidate_transitions_path or not os.path.exists(self.candidate_transitions_path):
            return
        try:
            with open(self.candidate_transitions_path, 'r') as f:
                data = json.load(f)
            for t in data.get('transitions', []):
                tid = t.get('transition_id', '')
                barrier = t.get('barrier', {})
                cond = barrier.get('condition', {})
                self.candidate_transitions[tid] = {
                    'desired_outcome': barrier.get('desired_outcome'),
                    'direction_source': barrier.get('direction_source', 'unknown'),
                    'true_successor_bb': barrier.get('true_successor_bb'),
                    'false_successor_bb': barrier.get('false_successor_bb'),
                    'distance_true': barrier.get('distance_true'),
                    'distance_false': barrier.get('distance_false'),
                    'barrier_type': barrier.get('type', ''),
                    'condition': {
                        'available': cond.get('available', False),
                        'kind': cond.get('kind', 'unknown'),
                        'predicate': cond.get('predicate'),
                        'lhs': cond.get('lhs'),
                        'rhs': cond.get('rhs'),
                    } if cond.get('available') and cond.get('lhs') is not None else None,
                }
            self.candidate_transitions_raw = data  # store raw for distance ranking
            if self.verbose:
                with_do = sum(1 for v in self.candidate_transitions.values()
                             if v['desired_outcome'] is not None)
                print(f"[INFO] Loaded {len(self.candidate_transitions)} candidate transitions "
                      f"({with_do} with desired_outcome)")
        except Exception as e:
            print(f"[WARN] Failed to load candidate transitions: {e}")

    def _load_semantics(self):
        """Load precomputed state_semantics.json."""
        if not self.state_semantics_path or not os.path.exists(self.state_semantics_path):
            return
        try:
            with open(self.state_semantics_path, 'r') as f:
                self.state_semantics = json.load(f)
        except (IOError, json.JSONDecodeError):
            self.state_semantics = {'_error': 'failed_to_load'}

    def scan_once(self):
        """Perform one scan cycle. Returns number of new sidecars processed."""
        t0 = time.time()
        state_to_tid = self.state_map.get('_state_to_tid', {})
        new_files = discover_sidecars(self.queue_dir, self.index)
        for fpath, data in new_files:
            data['_sidecar_path'] = fpath
            try:
                self.stats.ingest(data, state_to_tid)
            except Exception:
                self.stats.parse_errors += 1
                self.errors_log.append(f"ingest error: {traceback.format_exc()}")

        elapsed_ms = int((time.time() - t0) * 1000)
        return len(new_files), elapsed_ms

    def export_all(self, elapsed_ms):
        """Export all online_*.json files atomically."""
        self.version += 1
        v = self.version

        # Ensure state_map is loaded
        if not self.state_map:
            self.reload_state_map()

        # online_stsr.json
        atomic_write_json(
            os.path.join(self.out_dir, 'online_stsr.json'),
            build_online_stsr(self.stats, v, self.state_map))

        # online_barrier_ranking.json (distance-based)
        atomic_write_json(
            os.path.join(self.out_dir, 'online_barrier_ranking.json'),
            build_online_barrier_ranking(self.stats, v,
                candidate_transitions=self.candidate_transitions_raw))

        # online_seed_buckets.json
        atomic_write_json(
            os.path.join(self.out_dir, 'online_seed_buckets.json'),
            build_online_seed_buckets(self.stats, v, self.top_k))

        # online_transition_runtime_context.json
        atomic_write_json(
            os.path.join(self.out_dir, 'online_transition_runtime_context.json'),
            build_online_transition_runtime_context(
                self.stats, v, self.state_map, self.source_root, self.top_k,
                state_semantics=self.state_semantics,
                candidate_transitions=self.candidate_transitions))

        # online_monitor_status.json
        atomic_write_json(
            os.path.join(self.out_dir, 'online_monitor_status.json'),
            build_online_monitor_status(self.stats, v, self.queue_dir,
                                        self.out_dir, elapsed_ms, self.errors_log))

    def run_once(self):
        """One-shot mode: process current sidecars and exit."""
        if self.verbose:
            print(f"[INFO] One-shot scan of {self.queue_dir}")

        self.reload_state_map()
        new_count, elapsed_ms = self.scan_once()
        self.export_all(elapsed_ms)

        tids = self.stats.all_tids()
        if self.verbose:
            print(f"[INFO] Processed {new_count} new sidecars "
                  f"(total: {self.stats.total_sidecars})")
            print(f"[INFO] Transitions: {len(tids)}")
            if tids:
                print(f"[INFO] Active: {tids[0]} "
                      f"(pre={self.stats.pre_count[tids[0]]}, "
                      f"barrier={self.stats.barrier_count[tids[0]]}, "
                      f"post={self.stats.post_count[tids[0]]})")
                print(f"[INFO] STSR: {self.stats.get_stsr(tids[0]):.4f}")
            print(f"[INFO] Exported to {self.out_dir}")

        return self.stats.total_sidecars

    def run_daemon(self):
        """Daemon mode: continuously poll for new sidecars."""
        print(f"[INFO] Online monitor daemon started")
        print(f"[INFO]   queue: {self.queue_dir}")
        print(f"[INFO]   output: {self.out_dir}")
        print(f"[INFO]   interval: {self.interval}s")
        print(f"[INFO]   top-k: {self.top_k}")

        self.reload_state_map()

        try:
            while True:
                new_count, elapsed_ms = self.scan_once()

                if new_count > 0:
                    self.export_all(elapsed_ms)
                    if self.verbose:
                        tids = self.stats.all_tids()
                        active = tids[0] if tids else 'N/A'
                        print(f"[{time.strftime('%H:%M:%S')}] +{new_count} seeds "
                              f"(total={self.stats.total_sidecars}, "
                              f"v={self.version}, "
                              f"active={active})")

                time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\n[INFO] Shutting down daemon...")
            _, elapsed_ms = self.scan_once()
            self.export_all(elapsed_ms)
            print(f"[INFO] Final export: version={self.version}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="FTFuzz Online State-Transition Monitor",
    )
    parser.add_argument("--queue-dir", required=True,
                        help="AFL++ queue directory to watch")
    parser.add_argument("--out-dir", required=True,
                        help="Directory for online_*.json output files")
    parser.add_argument("--state-map", default=None,
                        help="Path to state_map.csv")
    parser.add_argument("--source-root", default=None,
                        help="Root directory of target source code")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Polling interval in seconds (default: 1.0)")
    parser.add_argument("--top-k", type=int, default=50,
                        help="Max seeds retained per transition/class (default: 50)")
    parser.add_argument("--daemon", action="store_true",
                        help="Run continuously in daemon mode")
    parser.add_argument("--once", action="store_true",
                        help="Process current sidecars once and exit")
    parser.add_argument("--state-semantics", default=None,
                        help="Path to precomputed state_semantics.json")
    parser.add_argument("--candidate-transitions", default=None,
                        help="Path to candidate_transitions.refined.json (for branch direction metadata)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print update information")
    args = parser.parse_args()

    if not os.path.isdir(args.queue_dir):
        if args.daemon:
            print(f"[WARN] Queue directory not found: {args.queue_dir}, "
                  f"waiting for it to appear...")
            while not os.path.isdir(args.queue_dir):
                time.sleep(1.0)
            print(f"[INFO] Queue directory appeared: {args.queue_dir}")
        else:
            print(f"[ERROR] Queue directory not found: {args.queue_dir}",
                  file=sys.stderr)
            sys.exit(1)

    monitor = OnlineMonitor(
        queue_dir=args.queue_dir,
        out_dir=args.out_dir,
        state_map_path=args.state_map,
        source_root=args.source_root,
        interval=args.interval,
        top_k=args.top_k,
        verbose=args.verbose,
        state_semantics_path=args.state_semantics,
        candidate_transitions_path=args.candidate_transitions,
    )

    if args.daemon:
        monitor.run_daemon()
    else:
        # Default to one-shot if --once or neither flag is set
        monitor.run_once()


if __name__ == "__main__":
    main()
