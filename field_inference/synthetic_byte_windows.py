#!/usr/bin/env python3
"""
Synthetic byte-window generation for controlled validation.

When real seed buckets are too sparse to produce meaningful byte windows,
generate windows using real seed byte statistics + semantic hints.

Produces byte_windows.json with synthetic ranges suitable for testing
the range-aware mutator pipeline.

Usage:
  python3 field_inference/synthetic_byte_windows.py \\
      --policy-store policy_store_v2.json \\
      --queue-dir /path/to/queue \\
      --output byte_windows.json \\
      --grounded-store grounded_policy_store_v2.json
"""

import argparse, json, os, sys, time


def load_json(path):
    with open(path) as f:
        text = f.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.JSONDecoder().raw_decode(text)[0]


def atomic_write(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)


def compute_byte_stability(queue_dir, max_seeds=100, max_size=2048):
    """Compute per-byte-position stability from real seeds."""
    seed_files = [f for f in os.listdir(queue_dir)
                  if f.startswith('id:') and not f.endswith(('.ftstate.json', '.state'))][:max_seeds]
    if not seed_files:
        return {}, 0

    all_data = []
    for sf in seed_files:
        try:
            with open(os.path.join(queue_dir, sf), 'rb') as f:
                all_data.append(f.read(max_size))
        except IOError:
            continue

    if not all_data:
        return {}, 0

    max_len = max(len(d) for d in all_data)
    stability = {}
    for pos in range(0, max_len, 8):
        byte_vals = {}
        count = 0
        for d in all_data:
            if pos < len(d):
                # Look at the byte + few around it
                window = d[max(0, pos-2):min(len(d), pos+14)]
                key = window.hex()[:32]
                byte_vals[key] = byte_vals.get(key, 0) + 1
                count += 1
        if count > 0:
            dominant = max(byte_vals.values()) / count
            stability[pos] = {'stability': round(dominant, 3), 'count': count}
    return stability, max_len


def generate_synthetic(ps, queue_dir, args):
    """Generate synthetic byte windows for each policy group."""
    stability, max_len = compute_byte_stability(queue_dir, max_seeds=200)

    output_groups = {}
    for gid, g in ps.get('policy_groups', {}).items():
        tokens = g.get('mutation_actions', {}).get('dictionary_tokens', [])
        token_names = [t.get('token', t) if isinstance(t, dict) else t for t in tokens]
        sem = g.get('semantic_basis', {}).get('transition_constraints', {})
        preserve_hints = sem.get('preserve', [])

        # Find stable header region (first 64 bytes typically stable XML header)
        preserve_ranges = []
        stable_positions = sorted(
            [(pos, info['stability']) for pos, info in stability.items()
             if info['stability'] > 0.7 and info['count'] >= 3],
            key=lambda x: x[1], reverse=True)

        if stable_positions and max_len > 0:
            # Create preserve ranges from stable regions
            merged = []
            current_start = None
            current_end = None
            current_stab = 0
            for pos, stab in sorted(stable_positions, key=lambda x: x[0]):
                if current_start is None:
                    current_start = pos
                    current_end = pos + 16
                    current_stab = stab
                elif pos <= current_end + 16:
                    current_end = max(current_end, pos + 16)
                    current_stab = max(current_stab, stab)
                else:
                    merged.append((current_start, current_end, current_stab))
                    current_start = pos
                    current_end = pos + 16
                    current_stab = stab
            if current_start is not None:
                merged.append((current_start, current_end, current_stab))

            for start, end, stab in merged[:8]:
                preserve_ranges.append({
                    'start': start, 'end': min(end, max_len), 'length': min(end - start, max_len - start),
                    'role': 'pre_state_preserving_region',
                    'source': ['synthetic_byte_stability', 'semantic_hint'],
                    'confidence': round(stab * 0.8, 4),
                    'evidence': {'stability_score': round(stab, 4), 'method': 'synthetic_byte_stability'},
                })

        # Focus ranges: middle section where variation matters
        focus_ranges = []
        if max_len > 32:
            mid_start = max(16, len(preserve_ranges) > 0 and preserve_ranges[-1]['end'] or 32)
            focus = [
                {'start': mid_start, 'end': min(mid_start + 64, max_len),
                 'confidence': 0.55, 'role': 'barrier_related_region',
                 'source': ['synthetic_focus'], 'length': 64},
                {'start': max(mid_start + 64, mid_start + 32), 'end': min(mid_start + 128, max_len),
                 'confidence': 0.45, 'role': 'barrier_related_region',
                'source': ['synthetic_focus'], 'length': 64},
            ]
            for f in focus:
                if f['end'] > f['start'] and f['start'] < max_len:
                    focus_ranges.append({
                        'start': f['start'], 'end': f['end'], 'length': f['end'] - f['start'],
                        'role': f['role'],
                        'source': f['source'],
                        'confidence': f['confidence'],
                        'evidence': {'method': 'synthetic_heuristic'},
                    })

        # Insert ranges from focus ranges
        insert_ranges = []
        for fr in focus_ranges[:4]:
            insert_ranges.append({
                'start': fr['start'], 'end': fr['end'], 'length': fr['length'],
                'tokens': token_names[:5],
                'confidence': round(fr['confidence'] * 0.9, 4),
                'source': 'synthetic_focus',
            })

        seed_stats = {'synthetic': len(stability), 'max_length': max_len}
        output_groups[gid] = {
            'group_id': gid,
            'member_transitions': g.get('member_transitions', []),
            'seed_stats': seed_stats,
            'preserve_ranges': preserve_ranges,
            'focus_ranges': focus_ranges,
            'preferred_insert_ranges': insert_ranges,
            'limitations': ['synthetic_validation', 'no_real_seed_bucket_matching'],
        }

    return {
        'schema_version': 'ftfuzz.byte_windows.v1',
        'generated_at_unix_ms': int(time.time() * 1000),
        'source': {'policy_store': args.policy_store, 'queue_dir': args.queue_dir},
        'parameters': {'synthetic': True, 'method': 'byte_stability_heuristic'},
        'policy_groups': output_groups,
    }


def ground_synthetic(ps, bw):
    """Inject synthetic windows into policy_store_v2."""
    ps = dict(ps)
    pg_out = {}
    for gid, g in ps.get('policy_groups', {}).items():
        g = dict(g)
        ma = dict(g.get('mutation_actions', {}))
        bw_group = bw.get('policy_groups', {}).get(gid, {})
        ma['preserve_ranges'] = bw_group.get('preserve_ranges', [])
        ma['focus_ranges'] = bw_group.get('focus_ranges', [])
        ma['preferred_insert_ranges'] = bw_group.get('preferred_insert_ranges', [])
        has_ranges = bool(ma['preserve_ranges'] or ma['focus_ranges'])
        if has_ranges:
            ma['operator_weights'] = {
                'dictionary_insert': 0.20, 'region_focus': 0.30,
                'fallback_havoc': 0.15, 'preserve_aware_havoc': 0.25,
                'numeric_boundary': 0.05, 'repair': 0.05,
            }
        g['mutation_actions'] = ma
        pg_out[gid] = g
    ps['policy_groups'] = pg_out
    ps['store_version'] = ps.get('store_version', 0) + 1
    ps['updated_at_unix_ms'] = int(time.time() * 1000)
    meta = dict(ps.get('metadata', {}))
    meta['grounded'] = True
    meta['synthetic'] = True
    meta['grounded_by'] = 'synthetic_byte_windows.py'
    ps['metadata'] = meta
    return ps


def main():
    p = argparse.ArgumentParser(description='Synthetic Byte Windows Generator')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--queue-dir', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--grounded-store', required=True)
    args = p.parse_args()

    ps = load_json(args.policy_store)
    bw = generate_synthetic(ps, args.queue_dir, args)
    atomic_write(args.output, bw)

    groups_with_ranges = sum(1 for g in bw['policy_groups'].values()
                             if g.get('preserve_ranges') or g.get('focus_ranges'))
    print(f'Synthetic byte_windows: groups={len(bw["policy_groups"])} with_ranges={groups_with_ranges}')
    for gid, g in bw['policy_groups'].items():
        print(f'  {gid}: preserve={len(g["preserve_ranges"])} focus={len(g["focus_ranges"])} insert={len(g["preferred_insert_ranges"])}')

    gs = ground_synthetic(ps, bw)
    atomic_write(args.grounded_store, gs)
    print(f'Grounded: v{gs["store_version"]}')
    print(f'Wrote {args.output} and {args.grounded_store}')


if __name__ == '__main__':
    main()
