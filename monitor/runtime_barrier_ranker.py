#!/usr/bin/env python3
"""
FTFuzz Runtime Barrier Ranker (Frontier-Aware)

Ranks transitions by how blocked they are, using fuzzing output data.
Identifies which transitions have many PreState hits but few PostState hits,
indicating a barrier that the fuzzer is struggling to pass.

Frontier-aware: only barriers at the current distance frontier
(closest reached distance to target) are prioritized for active intervention.
Barriers behind the frontier are deprioritized to "monitor" status.

Ranking score:
  base_score = w1 * pre_reach_count
             + w2 * blocked_count
             + w3 * (1 - stsr)
             + w4 * near_post_count
             - w5 * post_reach_count

  final_score = base_score * frontier_tier_multiplier

Default weights: w1=0.2, w2=1.0, w3=2.0, w4=0.5, w5=0.5

Usage:
  python3 monitor/runtime_barrier_ranker.py /path/to/ftfuzz_out/default/queue
  python3 monitor/runtime_barrier_ranker.py /path/to/ftfuzz_out/default/queue --stsr-report stsr_report.json
  python3 monitor/runtime_barrier_ranker.py /path/to/ftfuzz_out/default/queue --candidate-transitions candidate_transitions.refined.json
  python3 monitor/runtime_barrier_ranker.py /path/to/ftfuzz_out/default/queue --output barrier_ranking.json
"""

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from monitor.state_classes import classify_transition, normalize_state_class


DEFAULT_WEIGHTS = {
    'w1': 0.2,   # pre_reach_count
    'w2': 1.0,   # blocked_count
    'w3': 2.0,   # (1 - stsr)
    'w4': 0.5,   # near_post_count
    'w5': 0.5,   # post_reach_count (negative = better)
}


def load_ftstate_files(queue_dir):
    """Load all .ftstate.json sidecar files."""
    seeds = []
    for fname in os.listdir(queue_dir):
        if fname.endswith('.ftstate.json'):
            fpath = os.path.join(queue_dir, fname)
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                    seeds.append(data)
            except (IOError, json.JSONDecodeError):
                pass
    return seeds


def load_stsr_report(path):
    """Load stsr_report.json."""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None


def compute_ranking(seeds, stsr_report=None, weights=None,
                    candidate_transitions=None):
    """Compute frontier-aware barrier ranking from seed sidecars and STSR report.

    Args:
        seeds: list of .ftstate.json sidecar dicts
        stsr_report: optional precomputed STSR report
        weights: optional weight dict overriding DEFAULT_WEIGHTS
        candidate_transitions: optional candidate_transitions.refined.json dict
            providing per-transition distance data for frontier calculation
    """
    w = weights or DEFAULT_WEIGHTS

    # Aggregate per-transition stats from sidecars
    transition_stats = defaultdict(lambda: {
        'pre_reach_count': 0,
        'barrier_reach_count': 0,
        'post_reach_count': 0,
        'blocked_count': 0,
        'near_post_count': 0,
        'fail_pre_count': 0,
    })

    for seed in seeds:
        transitions = seed.get('transitions', {})
        for tid, tdata in transitions.items():
            pre = tdata.get('pre_hit', False)
            bar = tdata.get('barrier_hit', False)
            post = tdata.get('post_hit', False)
            ts = transition_stats[tid]

            if pre:
                ts['pre_reach_count'] += 1
            if pre and bar:
                ts['barrier_reach_count'] += 1
            if pre and post:
                ts['post_reach_count'] += 1
            if pre and bar and not post:
                ts['blocked_count'] += 1
                ts['near_post_count'] += 1
            if not pre:
                ts['fail_pre_count'] += 1

    # Get STSR from report if available, otherwise compute from sidecars
    stsr_map = {}
    if stsr_report and 'transitions' in stsr_report:
        for tid, tstats in stsr_report['transitions'].items():
            stsr_map[tid] = tstats.get('stsr', 0.0)
    else:
        for tid, ts in transition_stats.items():
            pre = ts['pre_reach_count']
            post = ts['post_reach_count']
            stsr_map[tid] = post / pre if pre > 0 else 0.0

    # ---- Frontier distance calculation ----
    # Load per-transition pre_state distance from candidate_transitions
    tid_pre_distance = {}
    if candidate_transitions:
        for t in candidate_transitions.get('transitions', []):
            tid = t.get('transition_id', '')
            pre_dist = t.get('pre_state', {}).get('distance', float('inf'))
            if pre_dist > 0 and pre_dist < float('inf'):
                tid_pre_distance[tid] = pre_dist

    # frontier = minimum pre_state distance among all REACHED barriers
    FRONTIER_WINDOW = 3.0
    frontier_dist = float('inf')
    for tid, ts in transition_stats.items():
        if ts['barrier_reach_count'] > 0:
            pre_dist = tid_pre_distance.get(tid, float('inf'))
            if pre_dist < frontier_dist:
                frontier_dist = pre_dist

    # Fallback: if no barrier reached, use minimum pre_dist among all
    if frontier_dist == float('inf'):
        all_pre = [d for d in tid_pre_distance.values() if d < float('inf')]
        frontier_dist = min(all_pre) if all_pre else 0.0

    # ---- Compute ranking scores with frontier awareness ----
    ranked = []
    for tid, ts in sorted(transition_stats.items()):
        stsr = stsr_map.get(tid, 0.0)

        # Base score (unchanged formula)
        base_score = (
            w['w1'] * ts['pre_reach_count']
            + w['w2'] * ts['blocked_count']
            + w['w3'] * (1.0 - stsr)
            + w['w4'] * ts['near_post_count']
            - w['w5'] * ts['post_reach_count']
        )

        # Frontier-aware tier classification and multiplier
        pre_dist = tid_pre_distance.get(tid, float('inf'))
        dist_to_frontier = pre_dist - frontier_dist
        is_reached = ts['barrier_reach_count'] > 0
        is_blocked = ts['blocked_count'] > 0

        if is_reached and dist_to_frontier <= FRONTIER_WINDOW:
            # At the frontier
            if is_blocked:
                tier = 'frontier_active'
                multiplier = 1.8
                action = 'active_obstacle'
                reason = (f'FRONTIER OBSTACLE: dist={pre_dist:.1f}, '
                          f'{ts["blocked_count"]} blocked, needs field inference')
            else:
                tier = 'frontier_passing'
                multiplier = 1.0
                action = 'frontier_passing'
                reason = f'Frontier barrier passing (dist={pre_dist:.1f})'
        elif is_reached and dist_to_frontier > FRONTIER_WINDOW:
            # Behind frontier — already passed this distance
            tier = 'behind_frontier'
            multiplier = 0.2
            action = 'monitor'
            reason = (f'Behind frontier (dist={pre_dist:.1f} > '
                      f'frontier={frontier_dist:.1f})')
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
            # Distant and unreached
            tier = 'distant'
            multiplier = 0.1
            action = 'monitor'
            reason = f'Distant unreached barrier (dist={pre_dist:.1f})'

        final_score = base_score * multiplier

        ranked.append({
            'transition_id': tid,
            'score': round(final_score, 2),
            'base_score': round(base_score, 2),
            'pre_reach_count': ts['pre_reach_count'],
            'barrier_reach_count': ts['barrier_reach_count'],
            'post_reach_count': ts['post_reach_count'],
            'blocked_count': ts['blocked_count'],
            'stsr': round(stsr, 4),
            'pre_state_distance': round(pre_dist, 1) if pre_dist < float('inf') else None,
            'frontier_distance': round(frontier_dist, 1) if frontier_dist < float('inf') else None,
            'distance_to_frontier': round(dist_to_frontier, 1) if dist_to_frontier < float('inf') else None,
            'tier': tier,
            'recommended_action': action,
            'reason': reason,
        })

    # Sort by score descending
    ranked.sort(key=lambda x: x['score'], reverse=True)

    return {
        'total_seeds': len(seeds),
        'weights': w,
        'frontier_distance': round(frontier_dist, 1) if frontier_dist < float('inf') else None,
        'ranked_transitions': ranked,
    }


def print_report(result):
    """Print ranking report."""
    print("=" * 70)
    print("FTFuzz Runtime Barrier Ranking (Frontier-Aware)")
    print("=" * 70)
    print(f"Total seeds: {result['total_seeds']}")
    print(f"Weights: {result['weights']}")
    fd = result.get('frontier_distance')
    if fd is not None:
        print(f"Frontier distance: {fd}")
    print()

    for r in result['ranked_transitions']:
        fd_str = f" frontier_dist={r.get('frontier_distance', 'N/A')}" if r.get('frontier_distance') is not None else ""
        print(f"  {r['transition_id']}: score={r['score']:.2f} "
              f"tier={r.get('tier', 'N/A')}{fd_str}")
        print(f"    Pre={r['pre_reach_count']}, Barrier={r['barrier_reach_count']}, "
              f"Post={r['post_reach_count']}, Blocked={r['blocked_count']}")
        print(f"    STSR={r['stsr']:.4f}, Action={r['recommended_action']}")
        if r.get('reason'):
            print(f"    Reason: {r['reason']}")
        print()

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="FTFuzz Runtime Barrier Ranker")
    parser.add_argument("queue_dir", help="Path to fuzzing queue directory")
    parser.add_argument("--stsr-report", default=None,
                        help="Path to stsr_report.json")
    parser.add_argument("--candidate-transitions", default=None,
                        help="Path to candidate_transitions.refined.json for distance data")
    parser.add_argument("--output", default=None,
                        help="Write JSON ranking to this file")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    args = parser.parse_args()

    if not os.path.isdir(args.queue_dir):
        print(f"[ERROR] Queue directory not found: {args.queue_dir}", file=sys.stderr)
        sys.exit(1)

    seeds = load_ftstate_files(args.queue_dir)
    if not seeds:
        print("[WARN] No .ftstate.json sidecar files found", file=sys.stderr)
        sys.exit(0)

    stsr_report = load_stsr_report(args.stsr_report) if args.stsr_report else None

    # Load candidate transitions for distance data
    candidate_transitions = None
    if args.candidate_transitions:
        try:
            with open(args.candidate_transitions, 'r') as f:
                candidate_transitions = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"[WARN] Failed to load candidate transitions: {e}", file=sys.stderr)

    result = compute_ranking(seeds, stsr_report,
                             candidate_transitions=candidate_transitions)

    if args.json or args.output:
        json_str = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_str)
            print(f"Ranking written to {args.output}")
        else:
            print(json_str)
    else:
        print_report(result)


if __name__ == "__main__":
    main()
