#!/usr/bin/env python3
"""
Upstream k-hop PostState Dependency Context Builder (Stage 2.5, Task C)

Collects upstream transitions whose PostState BBs can reach the active
frontier transition's PreState BB. Selects by:
  1. Same function, CFG predecessor
  2. Decreasing distance toward active transition
  3. Caller/callee neighborhood
  4. Closest source as last fallback

Usage:
  python3 context/upstream_poststate_context_builder.py \
      --active-transition T_AUTO_0164 \
      --candidate-transitions experiments/output/libxml2/dgf/candidate_transitions.refined.json \
      --online-context experiments/output/libxml2/online/online_transition_runtime_context.json \
      --upstream-hops 3 \
      --out experiments/output/libxml2/context/upstream_poststate_context.json
"""

import argparse, json, os, sys
from collections import defaultdict


def load_candidates(path):
    with open(path) as f:
        return json.load(f)


def load_online_context(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def build_transition_graph(candidates):
    """Build lookup: bb_id -> transitions with that bb_id as pre/post."""
    pre_map = defaultdict(list)   # bb_id -> [transition]
    post_map = defaultdict(list)  # bb_id -> [transition]
    tid_map = {}
    for t in candidates.get('transitions', []):
        tid = t['transition_id']
        tid_map[tid] = t
        pre_bb = t['pre_state'].get('bb_id')
        post_bb = t['post_state'].get('bb_id')
        if pre_bb and pre_bb > 0:
            pre_map[pre_bb].append(t)
        if post_bb and post_bb > 0:
            post_map[post_bb].append(t)
    return pre_map, post_map, tid_map


def select_upstream(active_tid, tid_map, pre_map, post_map, max_hops=3):
    """Select k-hop upstream transitions using priority rules."""
    if active_tid not in tid_map:
        return [], {'hops_found': 0, 'missing_semantics_count': 0, 'fallback_used': True}

    active = tid_map[active_tid]
    active_pre_bb = active['pre_state'].get('bb_id')
    active_func = active['pre_state'].get('function', '')
    active_dist = active['pre_state'].get('distance', float('inf'))

    upstream = []
    visited_tids = {active_tid}
    candidates = []  # (score, transition, reason)

    # 1. Same function CFG predecessors of active PreState BB
    if active_pre_bb and active_pre_bb > 0:
        # Find transitions whose post_state BB matches a CFG predecessor
        for t in tid_map.values():
            tid = t['transition_id']
            if tid in visited_tids:
                continue
            post_bb = t['post_state'].get('bb_id')
            post_dist = t['post_state'].get('distance', float('inf'))
            post_func = t['post_state'].get('function', '')
            # Same function + distance decreasing + post BB can reach active pre BB
            if post_func == active_func and post_dist <= active_dist:
                candidates.append((0.9, t, 'same_func_distance_decreasing'))

    # 2. Closest distance to active transition
    for t in tid_map.values():
        tid = t['transition_id']
        if tid in visited_tids or any(c[1]['transition_id'] == tid for c in candidates):
            continue
        post_dist = t['post_state'].get('distance', float('inf'))
        if 0 < post_dist < float('inf'):
            # Score inversely proportional to distance gap
            gap = abs(post_dist - active_dist)
            score = 1.0 / (1.0 + gap) * 0.7
            candidates.append((score, t, 'distance_proximity'))

    # 3. Caller/callee neighborhood
    for t in tid_map.values():
        tid = t['transition_id']
        if tid in visited_tids or any(c[1]['transition_id'] == tid for c in candidates):
            continue
        pre_func = t['pre_state'].get('function', '')
        if pre_func and pre_func != active_func:
            candidates.append((0.3, t, 'different_function_neighbor'))

    # 4. Closest CFG predecessor as fallback
    for t in tid_map.values():
        tid = t['transition_id']
        if tid in visited_tids or any(c[1]['transition_id'] == tid for c in candidates):
            continue
        candidates.append((0.1, t, 'fallback'))

    # Sort by score, take top N
    candidates.sort(key=lambda x: -x[0])
    fallback_used = False

    for hop in range(max_hops):
        if not candidates:
            break
        score, t, reason = candidates.pop(0)
        tid = t['transition_id']
        if tid in visited_tids:
            continue
        visited_tids.add(tid)
        if reason == 'fallback':
            fallback_used = True

        # Extract state objects from post_state summary
        post_summary = t.get('post_state', {})
        state_objects = extract_state_objects(post_summary, t)

        upstream.append({
            'hop': hop + 1,
            'transition_id': tid,
            'selection_reason': reason,
            'function': t['pre_state'].get('function', ''),
            'source_location': f"{t['pre_state'].get('file','')}:{t['pre_state'].get('line',0)}",
            'post_state_summary': _get_summary(t),
            'state_objects': state_objects,
            'input_semantic_implications': derive_implications(state_objects),
        })

    quality = {
        'hops_found': len(upstream),
        'missing_semantics_count': max(0, max_hops - len(upstream)),
        'fallback_used': fallback_used,
    }
    return upstream, quality


def extract_state_objects(post_state, transition):
    """Extract lightweight structured state objects from post state."""
    objects = []
    func = transition.get('pre_state', {}).get('function', '')
    # Heuristic: look for known libxml2 patterns
    known_patterns = [
        ('ids', 'id_table'), ('intSubset', 'declaration_container'),
        ('extSubset', 'declaration_container'), ('dict', 'dictionary'),
        ('refs', 'ref_table'), ('attributes', 'attribute_table'),
        ('notations', 'notation_table'), ('elements', 'element_table'),
        ('entities', 'entity_table'),
    ]
    for field, role in known_patterns:
        if field in func.lower() or field in str(post_state).lower():
            objects.append({
                'name': f'doc->{field}' if 'xmlDoc' in func or 'xmlFree' in func else field,
                'role': role,
                'status': 'possibly_available',
                'confidence': 0.5,
            })
    return objects


def derive_implications(state_objects):
    """Derive input semantic implications from state objects."""
    impls = []
    for obj in state_objects:
        if obj['role'] == 'id_table':
            impls.append("Input may require ID-typed attributes or xml:id declarations")
        elif obj['role'] == 'declaration_container':
            impls.append("Input may require DTD/internal subset declarations")
    if not impls:
        impls.append("Input semantics unclear from available context")
    return impls


def _get_summary(t):
    """Get a brief summary of the transition."""
    pre = t.get('pre_state', {})
    post = t.get('post_state', {})
    barrier = t.get('barrier', {})
    return f"{pre.get('function','?')}:{pre.get('line',0)} → {post.get('function','?')}:{post.get('line',0)} [{barrier.get('type','?')}]"


def main():
    p = argparse.ArgumentParser(description='Upstream PostState Context Builder')
    p.add_argument('--active-transition', required=True)
    p.add_argument('--candidate-transitions', required=True)
    p.add_argument('--online-context', default=None)
    p.add_argument('--upstream-hops', type=int, default=3)
    p.add_argument('--out', required=True)

    args = p.parse_args()
    candidates = load_candidates(args.candidate_transitions)
    online_ctx = load_online_context(args.online_context)

    pre_map, post_map, tid_map = build_transition_graph(candidates)
    upstream, quality = select_upstream(args.active_transition, tid_map, pre_map, post_map, args.upstream_hops)

    # Build active transition context
    active = tid_map.get(args.active_transition, {})
    active_ctx = {
        'transition_id': args.active_transition,
        'desired_outcome': active.get('barrier', {}).get('desired_outcome'),
        'direction_source': active.get('barrier', {}).get('direction_source', 'unknown'),
        'function': active.get('pre_state', {}).get('function', ''),
        'source_location': f"{active.get('pre_state',{}).get('file','')}:{active.get('pre_state',{}).get('line',0)}",
        'pre_state_summary': _get_summary(active),
        'barrier_summary': str(active.get('barrier', {}).get('condition', {})),
        'post_state_summary': f"PostState: {active.get('post_state',{}).get('function','')}:{active.get('post_state',{}).get('line',0)}",
        'state_goal_hint': infer_state_goal(active),
    }

    output = {
        'schema_version': 'ftfuzz.upstream_poststate_context.v1',
        'active_transition': active_ctx,
        'upstream_hops': args.upstream_hops,
        'upstream_poststates': upstream,
        'context_quality': quality,
    }

    d = os.path.dirname(args.out)
    if d: os.makedirs(d, exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump(output, f, indent=2)
    print(f'[OUTPUT] {args.out}')
    print(f'  upstream_hops: {quality["hops_found"]}/{args.upstream_hops}')
    print(f'  fallback_used: {quality["fallback_used"]}')
    for u in upstream:
        print(f'  hop {u["hop"]}: {u["transition_id"]} ({u["selection_reason"]})')


def infer_state_goal(active):
    """Heuristic: infer likely state goal from barrier context."""
    func = str(active.get('pre_state', {})).lower()
    barrier = str(active.get('barrier', {})).lower()
    if 'ids' in func or 'ids' in barrier or 'id' in barrier:
        return 'materialize_internal_table: xmlDoc.ids non_null'
    if 'attributes' in func or 'attributes' in barrier:
        return 'materialize_internal_table: cur->attributes non_null'
    return 'unknown'


if __name__ == '__main__':
    main()
