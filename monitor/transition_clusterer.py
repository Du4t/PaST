#!/usr/bin/env python3
"""Cluster similar blocked transitions and select representatives (Stage 2.1-pre).

Usage:
  python3 monitor/transition_clusterer.py \\
      --blocked blocked_transitions.json \\
      --online-context online_transition_runtime_context.json \\
      --output representative_transitions.json
"""

import argparse, hashlib, json
from collections import defaultdict
from datetime import datetime, timezone


def signature(tr, online_context):
    """Generate a transition signature for clustering."""
    trans = online_context.get('transitions', {}).get(tr['transition_id'], {})
    pre = trans.get('pre_state', {})
    bar = trans.get('barrier', {})
    post = trans.get('post_state', {})

    func = bar.get('function', '') or pre.get('function', '')
    bfile = bar.get('file', '')
    bline = bar.get('line', 0)

    pre_txt = pre.get('snippet', {}).get('text', '')
    bar_txt = bar.get('snippet', {}).get('text', '')
    cond = bar.get('condition', {}).get('kind', '')

    h = hashlib.md5(f"{func}|{bfile}|{bline}|{cond}|{pre_txt}|{bar_txt}".encode()).hexdigest()[:12]
    return h, func, bfile, bline


def cluster(blocked_list, online_context, line_window=5, max_per_func=5, max_reps=10):
    clusters = defaultdict(list)
    trans_map = {t['transition_id']: t for t in blocked_list}

    for t in blocked_list:
        sig, func, bfile, bline = signature(t, online_context)
        # Key: function + file + signature prefix
        key = f"{func}|{bfile}|{sig[:8]}"
        found = False
        # Try exact signature match first
        if sig in clusters:
            clusters[sig].append(t['transition_id'])
            continue
        # Try nearby line match
        for existing_sig, members in list(clusters.items()):
            if len(members) >= max_per_func:
                continue
            # Check if same function
            for mid in members:
                mt = trans_map.get(mid)
                if not mt:
                    continue
                _, mfunc, mfile, mline = signature(mt, online_context)
                if func == mfunc and bfile == mfile and abs(bline - mline) <= line_window:
                    clusters[existing_sig].append(t['transition_id'])
                    found = True
                    break
            if found:
                break
        if not found:
            clusters[sig].append(t['transition_id'])

    # Select representatives, sorted by highest blocked_score per cluster
    reps = []
    # Sort clusters by their best member's score (not by signature hash)
    def cluster_best_score(sig_members):
        sig, members = sig_members
        return -max(trans_map[tid]['blocked_score'] for tid in members if tid in trans_map)

    for sig, members in sorted(clusters.items(), key=cluster_best_score):
        if len(reps) >= max_reps:
            break
        # Pick member with highest blocked_score
        best_tid = max(members, key=lambda tid: trans_map[tid]['blocked_score'])
        reps.append({
            'cluster_id': f'CL_{len(reps)+1:04d}',
            'signature': sig,
            'representative_transition': best_tid,
            'member_transitions': members,
            'function': signature(trans_map[best_tid], online_context)[1],
            'reason': f'{len(members)} similar transitions in same function',
        })

    return {
        'schema_version': 'ftfuzz.representative_transitions.v1',
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'summary': {
            'blocked_transition_count': len(blocked_list),
            'cluster_count': len(reps),
            'representative_count': len(reps),
        },
        'clusters': reps,
    }


def main():
    p = argparse.ArgumentParser(description='Transition Clusterer')
    p.add_argument('--blocked', required=True)
    p.add_argument('--online-context', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()

    blocked = json.load(open(args.blocked))
    ctx = json.load(open(args.online_context))
    result = cluster(blocked.get('blocked_transitions', []), ctx)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2, default=str)

    s = result['summary']
    print(f'Clusters: {s["cluster_count"]} from {s["blocked_transition_count"]} blocked, '
          f'{s["representative_count"]} representatives')
    for cl in result['clusters'][:5]:
        print(f'  {cl["cluster_id"]}: rep={cl["representative_transition"]} '
              f'members={cl["member_transitions"]} ({cl["reason"]})')


if __name__ == '__main__':
    main()
