#!/usr/bin/env python3
"""Select blocked transitions based on runtime evidence (Stage 2.1-pre).

Usage:
  python3 monitor/blocked_transition_selector.py \\
      --online-context online_transition_runtime_context.json \\
      --online-stsr online_stsr.json \\
      --online-barrier-ranking online_barrier_ranking.json \\
      --output blocked_transitions.json --top-k 20
"""

import argparse, json, sys
from datetime import datetime, timezone
from collections import defaultdict

DEFAULTS = dict(MIN_PRE=20, MIN_BARRIER=5, MAX_STSR=0.20, MIN_BLOCKED=3,
                POST_SAT=50, TOP_K=20)


def select_blocked(online_context, online_stsr, barrier_ranking, top_k=20,
                   min_pre=1, min_barrier=1, max_stsr=0.20, min_blocked=1,
                   post_sat=50):
    """Select blocked transitions. Uses distance-based ranking from barrier_ranking
    as primary signal, runtime evidence as secondary."""
    transitions = online_context.get('transitions', {})
    stsr_data = online_stsr.get('transitions', {})
    ranking_list = barrier_ranking.get('ranked_transitions', [])

    # Build ranking lookup: tid -> rank info (distance, score, etc.)
    rank_map = {}
    for r in ranking_list:
        rank_map[r['transition_id']] = r

    # Use distance-based ranking as primary ordering
    candidates = []
    for r in ranking_list[:top_k * 3]:  # consider 3x top-k for filtering
        tid = r['transition_id']
        bar = r.get('barrier_count', 0)
        post = r.get('post_count', 0)
        stsr = r.get('stsr', 0)
        dist = r.get('distance_to_target', 999)

        is_blocked = (bar >= min_barrier and post == 0)

        candidates.append({
            'transition_id': tid,
            'pre_count': r.get('pre_count', 0),
            'barrier_count': bar, 'post_count': post, 'stsr': stsr,
            'distance_to_target': dist,
            'is_blocked': is_blocked,
            'rank_score': r.get('score', 0),
            'blocked_score': r.get('score', 0),  # use ranking score directly
        })

    # Filter: only keep genuinely blocked transitions (bar>0, post==0)
    blocked_candidates = [c for c in candidates if c['is_blocked']]
    # Sort by ranking score (already distance-based + blocked bonus)
    blocked_candidates.sort(key=lambda c: -c['blocked_score'])

    blocked_count = len(blocked_candidates)

    result = {
        'schema_version': 'ftfuzz.blocked_transitions.v1',
        'generated_at': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'summary': {
            'total_transitions': len(transitions),
            'candidates_scored': len(blocked_candidates),
            'blocked_count': blocked_count,
            'top_k': min(top_k, len(blocked_candidates)),
        },
        'blocked_transitions': blocked_candidates[:top_k],
    }
    return result


def main():
    p = argparse.ArgumentParser(description='Blocked Transition Selector')
    p.add_argument('--online-context', required=True)
    p.add_argument('--online-stsr', required=True)
    p.add_argument('--online-barrier-ranking', default=None)
    p.add_argument('--output', required=True)
    p.add_argument('--top-k', type=int, default=20)
    p.add_argument('--min-pre', type=int, default=20)
    p.add_argument('--min-barrier', type=int, default=5)
    p.add_argument('--max-stsr', type=float, default=0.20)
    args = p.parse_args()

    ctx = json.load(open(args.online_context))
    stsr = json.load(open(args.online_stsr))
    ranking = json.load(open(args.online_barrier_ranking)) if args.online_barrier_ranking and __import__('os').path.exists(args.online_barrier_ranking) else {'ranked_transitions': []}

    result = select_blocked(ctx, stsr, ranking, args.top_k,
                            args.min_pre, args.min_barrier, args.max_stsr)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2, default=str)

    s = result['summary']
    print(f'Blocked: {s["blocked_count"]}/{s["total_transitions"]} transitions, '
          f'top {s["top_k"]} written to {args.output}')
    for c in result['blocked_transitions'][:5]:
        print(f'  {c["transition_id"]}: score={c["blocked_score"]:.2f} '
              f'pre={c["pre_count"]} bar={c["barrier_count"]} stsr={c["stsr"]:.3f}')


if __name__ == '__main__':
    main()
