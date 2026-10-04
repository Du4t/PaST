#!/usr/bin/env python3
"""
FTFuzz Byte-Window Field Inference (Stage 2.1)

Infers byte-level preserve_ranges, focus_ranges, and preferred_insert_ranges
for each policy group by analyzing seed buckets and their state transitions.

Algorithm:
  1. Load policy_group_seed_buckets.json
  2. For each policy group, score sliding windows:
     - preserve: stability across progressed seeds (Reach-Pre, Blocked-at-Barrier)
     - focus: difference between Reach-Pre and Blocked-at-Barrier seeds
  3. Merge adjacent windows into ranges
  4. Output byte_windows.json

Usage:
  python3 field_inference/byte_window_infer.py \\
      --buckets policy_group_seed_buckets.json \\
      --policy-store policy_store_v2.json \\
      --state-map state_map_auto.csv \\
      --output byte_windows.json \\
      --window-size 16 --stride 8
"""

import argparse, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from field_inference.window_scoring import (
    score_preserve_windows, score_focus_windows, merge_ranges
)


def load_json(path):
    with open(path) as f:
        text = f.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        return decoder.raw_decode(text)[0]


def infer_windows_for_group_real(gid, buckets, policy_group, args):
    """Infer byte windows from real seed buckets (non-synthetic)."""
    preserve_ranges = []
    focus_ranges = []
    insert_ranges = []

    reach_pre = buckets.get('Reach-Pre', [])
    blocked = (buckets.get('Blocked-at-Barrier', []) +
               buckets.get('Barrier-Reached', []))
    post = buckets.get('Reach-Post', []) + buckets.get('Progressed-Through-Barrier', [])
    fail_pre = buckets.get('Fail-Pre', [])

    tokens = policy_group.get('mutation_actions', {}).get('dictionary_tokens', [])
    token_names = []
    token_bytes = []
    for t in tokens:
        tok = t.get('token', '') if isinstance(t, dict) else str(t)
        token_names.append(tok)
        token_bytes.append(tok.encode()[:16] if tok else b'')

    token_bytes = [t for t in token_bytes if t]

    # 1. Preserve: stability across progressed seeds (Reach-Pre + Barrier-Reached)
    progress = reach_pre + blocked + post
    if len(progress) >= args.min_support:
        from field_inference.window_scoring import score_preserve_windows, merge_ranges
        preserve_candidates = score_preserve_windows(
            progress, args.window_size, args.stride,
            args.max_seed_size, token_bytes)
        preserve_candidates = [w for w in preserve_candidates
                               if w['score'] >= args.threshold_preserve
                               and w['coverage'] >= args.min_support]
        preserve_ranges = merge_ranges(preserve_candidates, args.stride, 16)

    # 2. Focus: differences between state classes
    from field_inference.window_scoring import score_focus_windows, merge_ranges
    focus_candidates = []

    # Reach-Pre vs Barrier-Reached/Blocked
    if len(reach_pre) >= args.min_support and len(blocked) >= args.min_support:
        fc = score_focus_windows(reach_pre, blocked, args.window_size, args.stride,
                                 args.max_seed_size, token_bytes)
        focus_candidates.extend(fc)

    # Fail-Pre vs Reach-Pre
    if len(fail_pre) >= args.min_support and len(reach_pre) >= args.min_support:
        fc = score_focus_windows(fail_pre, reach_pre, args.window_size, args.stride,
                                 args.max_seed_size, token_bytes)
        focus_candidates.extend(fc)

    # Barrier-Reached vs Reach-Post
    if len(blocked) >= args.min_support and len(post) >= args.min_support:
        fc = score_focus_windows(blocked, post, args.window_size, args.stride,
                                 args.max_seed_size, token_bytes)
        focus_candidates.extend(fc)

    focus_candidates = [w for w in focus_candidates
                        if w['score'] >= args.threshold_focus
                        and w['coverage'] >= args.min_support]
    focus_ranges = merge_ranges(focus_candidates, args.stride, 16)

    # 3. Insert ranges from focus ranges
    for fr in focus_ranges[:8]:
        insert_ranges.append({
            'start': fr['start'], 'end': fr['end'], 'length': fr['length'],
            'tokens': token_names[:5],
            'confidence': round(fr['score'] * 0.9, 4),
            'source': 'real_focus_range',
        })

    # Format evidence for output
    for r in preserve_ranges:
        r['role'] = 'pre_state_preserving_region'
        r['source'] = ['real_bucket_stability']
        r['synthetic'] = False
        r['evidence'] = {'stability_score': r.get('stability', r.get('score', 0))}

    for r in focus_ranges:
        r['role'] = 'barrier_related_region'
        r['source'] = ['real_bucket_diff']
        r['synthetic'] = False
        r['evidence'] = {'difference_score': r.get('difference', r.get('score', 0))}

    return preserve_ranges, focus_ranges, insert_ranges


def infer_windows_for_group(gid, buckets, policy_group, args):
    """Infer byte windows for a single policy group."""
    preserve_candidates = []
    focus_candidates = []
    insert_candidates = []

    # Collect progress seeds for preserve scoring
    progress_seeds = []
    for cls in ['Reach-Pre', 'Blocked-at-Barrier', 'Barrier-Reached',
                'Progressed-Through-Barrier', 'Reach-Post']:
        for sd in buckets.get(cls, []):
            progress_seeds.append(sd)

    reach_pre_seeds = buckets.get('Reach-Pre', [])
    blocked_seeds = buckets.get('Blocked-at-Barrier', []) + buckets.get('Barrier-Reached', [])
    post_seeds = buckets.get('Reach-Post', [])

    # Semantic hints from policy group
    sem_hints = policy_group.get('semantic_basis', {}).get('transition_constraints', {})
    preserve_keywords = sem_hints.get('preserve', [])
    focus_keywords = sem_hints.get('mutate_focus', [])
    tokens = policy_group.get('mutation_actions', {}).get('dictionary_tokens', [])
    token_strs = []
    token_names = []
    for t in tokens:
        if isinstance(t, dict):
            tok = t.get('token', '')
            token_strs.append(tok.encode()[:16] if tok else b'')
            token_names.append(tok)
        elif isinstance(t, str):
            token_strs.append(t.encode()[:16])
            token_names.append(t)

    semantic_hint_bytes = [t[:16] for t in token_strs if t]  # use token bytes as semantic hints

    # 1. Preserve scoring
    if progress_seeds:
        preserve_candidates = score_preserve_windows(
            progress_seeds, args.window_size, args.stride,
            args.max_seed_size, semantic_hint_bytes)
        preserve_candidates = [w for w in preserve_candidates
                               if w['score'] >= args.threshold_preserve
                               and w['coverage'] >= args.min_support]

    # 2. Focus scoring: Reach-Pre vs Blocked
    if reach_pre_seeds and blocked_seeds:
        focus_candidates = score_focus_windows(
            reach_pre_seeds, blocked_seeds,
            args.window_size, args.stride, args.max_seed_size, semantic_hint_bytes)
        focus_candidates = [w for w in focus_candidates
                            if w['score'] >= args.threshold_focus
                            and w['coverage'] >= args.min_support]

    # 3. Also try Blocked vs Post if post_seeds exist
    if blocked_seeds and post_seeds:
        post_candidates = score_focus_windows(
            blocked_seeds, post_seeds,
            args.window_size, args.stride, args.max_seed_size, semantic_hint_bytes)
        post_candidates = [w for w in post_candidates
                           if w['score'] >= args.threshold_focus]
        focus_candidates.extend(post_candidates)

    # Merge into ranges
    preserve_ranges = merge_ranges(preserve_candidates, args.stride, 32)
    focus_ranges = merge_ranges(focus_candidates, args.stride, 32)

    # Resolve conflicts: if a range appears in both preserve and focus
    for fr in focus_ranges:
        for pr in preserve_ranges:
            if fr['start'] < pr['end'] and pr['start'] < fr['end']:
                fr['conflict'] = 'overlaps_preserve'
                if fr['score'] < pr['score'] + 0.2:
                    fr['_suppressed'] = True
    focus_ranges = [r for r in focus_ranges if not r.get('_suppressed')]
    for r in focus_ranges:
        r.pop('_suppressed', None)

    # Preferred insert ranges from focus ranges
    for fr in focus_ranges[:8]:
        insert_candidates.append({
            'start': fr['start'], 'end': fr['end'],
            'length': fr['length'],
            'tokens': token_names[:5],
            'confidence': round(fr['score'] * 0.9, 4),
            'source': 'focus_range',
        })

    # Fallback: if no focus ranges, use non-preserve regions
    if not insert_candidates and preserve_ranges:
        preserved = set()
        for pr in preserve_ranges:
            for i in range(pr['start'], pr['end']):
                preserved.add(i)
        max_pos = max(pr['end'] for pr in preserve_ranges) + 128
        for start in range(0, max_pos, args.window_size):
            end = start + args.window_size * 2
            if not preserved or start > max(preserved) + 8:
                insert_candidates.append({
                    'start': start, 'end': end, 'length': end - start,
                    'tokens': token_names[:5],
                    'confidence': 0.4,
                    'source': 'fallback_non_preserve',
                })

    # Build per-range evidence
    for r in preserve_ranges:
        r['role'] = 'pre_state_preserving_region'
        r['source'] = ['state_bucket_stability']
        r['evidence'] = {'stability_score': r.get('stability', 0),
                         'coverage': r.get('coverage', 0)}
        r.pop('stability', None)
        r.pop('coverage', None)
        r.pop('max_support', None)

    for r in focus_ranges:
        r['role'] = 'barrier_related_region'
        r['source'] = ['between_bucket_difference']
        r['evidence'] = {'difference_score': r.get('difference', 0),
                         'correlation': r.get('correlation', 0)}
        r.pop('difference', None)
        r.pop('correlation', None)
        r.pop('coverage', None)
        r.pop('conflict', None)

    return preserve_ranges, focus_ranges, insert_candidates


def main():
    p = argparse.ArgumentParser(description='Byte-Window Field Inference')
    p.add_argument('--buckets', required=True, help='policy_group_seed_buckets.json')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--state-map', default=None)
    p.add_argument('--output', required=True, help='byte_windows.json')
    p.add_argument('--mode', default='auto', choices=['real-only', 'synthetic-only', 'auto'])
    p.add_argument('--window-size', type=int, default=32)
    p.add_argument('--stride', type=int, default=16)
    p.add_argument('--max-seed-size', type=int, default=4096)
    p.add_argument('--max-seeds-per-bucket', type=int, default=50)
    p.add_argument('--min-support', type=int, default=3)
    p.add_argument('--threshold-preserve', type=float, default=0.55)
    p.add_argument('--threshold-focus', type=float, default=0.45)
    args = p.parse_args()

    buckets_data = load_json(args.buckets)
    ps = load_json(args.policy_store)
    pg_buckets = buckets_data.get('policy_groups', {})

    synthetic = (args.mode == 'synthetic-only')
    output = {
        'schema_version': 'ftfuzz.byte_windows.v1',
        'generated_at_unix_ms': int(__import__('time').time() * 1000),
        'source': {
            'policy_store': args.policy_store,
            'buckets': args.buckets,
        },
        'synthetic': synthetic,
        'inference_mode': args.mode,
        'parameters': {
            'window_size': args.window_size, 'stride': args.stride,
            'min_support': args.min_support,
            'threshold_preserve': args.threshold_preserve,
            'threshold_focus': args.threshold_focus,
        },
        'policy_groups': {},
    }

    for gid, g in ps.get('policy_groups', {}).items():
        if gid not in pg_buckets:
            continue

        bg = pg_buckets[gid]

        if args.mode == 'real-only' or args.mode == 'auto':
            pres, foc, ins = infer_windows_for_group_real(gid, bg, g, args)
            if pres or foc or ins:
                output['synthetic'] = False
            elif args.mode == 'real-only':
                print(f'[FAIL] {gid}: no real ranges inferred (insufficient evidence)')
                pres, foc, ins = [], [], []
            else:
                # auto: fall back to synthetic
                print(f'[AUTO] {gid}: real ranges empty, using synthetic fallback')
                pres, foc, ins = infer_windows_for_group(gid, bg, g, args)
        else:
            pres, foc, ins = infer_windows_for_group(gid, bg, g, args)

        seed_stats = {cls: len(bg.get(cls, [])) for cls in
                      ['Fail-Pre', 'Reach-Pre', 'Blocked-at-Barrier',
                       'Barrier-Reached', 'Progressed-Through-Barrier', 'Reach-Post',
                       'Invalid-Post-Without-Pre']}

        output['policy_groups'][gid] = {
            'group_id': gid,
            'member_transitions': g.get('member_transitions', []),
            'evidence_summary': seed_stats,
            'preserve_ranges': pres,
            'focus_ranges': foc,
            'preferred_insert_ranges': ins,
            'limitations': _check_limitations(pres, foc, bg),
        }

        real_ranges = sum(1 for r in pres + foc + ins if not r.get('synthetic', True))
        print(f'{gid}: seeds={sum(seed_stats.values())} preserve={len(pres)} focus={len(foc)} insert={len(ins)} real_ranges={real_ranges}')

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f'Wrote {args.output}')


def _check_limitations(pres, foc, bg):
    lims = []
    if not pres and not foc:
        lims.append('no_ranges_inferred')
    total_seeds = sum(len(v) for v in bg.values())
    if total_seeds < 3:
        lims.append('sparse_seed_buckets')
    return lims


if __name__ == '__main__':
    main()
