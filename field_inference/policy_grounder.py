#!/usr/bin/env python3
"""
FTFuzz Policy Grounder — injects byte-window ranges into policy_store_v2.

Reads byte_windows.json and policy_store_v2.json, produces
grounded_policy_store_v2.json with per-policy-group preserve_ranges,
focus_ranges, and preferred_insert_ranges.

Usage:
  python3 field_inference/policy_grounder.py \\
      --policy-store policy_store_v2.json \\
      --byte-windows byte_windows.json \\
      --output grounded_policy_store_v2.json
"""

import argparse, json, os, sys


def load_json(path):
    with open(path) as f:
        text = f.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        return decoder.raw_decode(text)[0]


def atomic_write(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)


def ground(ps, bw, require_real=False):
    """Inject byte-window ranges into policy_store_v2.
    With require_real: only inject ranges with synthetic=false."""
    ps = dict(ps)
    pg_out = {}
    all_synthetic = True

    for gid, g in ps.get('policy_groups', {}).items():
        g = dict(g)
        ma = dict(g.get('mutation_actions', {}))
        bw_group = bw.get('policy_groups', {}).get(gid, {})

        pres = bw_group.get('preserve_ranges', [])
        foc = bw_group.get('focus_ranges', [])
        ins = bw_group.get('preferred_insert_ranges', [])

        if require_real:
            pres = [r for r in pres if not r.get('synthetic', True)]
            foc = [r for r in foc if not r.get('synthetic', True)]
            ins = [r for r in ins if not r.get('synthetic', True)]

        if pres or foc or ins:
            all_synthetic = False
            for r in pres + foc:
                if not r.get('synthetic', True):
                    all_synthetic = False
                    break

        ma['preserve_ranges'] = _clean_ranges(pres)
        ma['focus_ranges'] = _clean_ranges(foc)
        ma['preferred_insert_ranges'] = ins

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
    ps['updated_at_unix_ms'] = int(__import__('time').time() * 1000)

    meta = dict(ps.get('metadata', {}))
    meta['grounded'] = True
    meta['synthetic'] = all_synthetic
    meta['grounded_by'] = 'policy_grounder.py'
    meta['byte_window_source'] = 'byte_windows.json'
    if require_real:
        meta['require_real'] = True
    ps['metadata'] = meta
    return ps


def _clean_ranges(ranges):
    out = []
    for r in ranges:
        out.append({
            'start': r.get('start', 0), 'end': r.get('end', 0),
            'length': r.get('length', 0),
            'role': r.get('role', 'unknown'),
            'confidence': r.get('confidence', r.get('score', 0.5)),
        })
    return out


def main():
    p = argparse.ArgumentParser(description='Policy Grounder')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--byte-windows', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--require-real', action='store_true')
    args = p.parse_args()

    ps = load_json(args.policy_store)
    bw = load_json(args.byte_windows)
    grounded = ground(ps, bw, require_real=args.require_real)

    atomic_write(args.output, grounded)
    groups_with_ranges = sum(1 for g in grounded['policy_groups'].values()
                             if g['mutation_actions'].get('preserve_ranges')
                             or g['mutation_actions'].get('focus_ranges'))
    print(f'Grounded: v{grounded["store_version"]} groups={len(grounded["policy_groups"])} '
          f'with_ranges={groups_with_ranges}')
    print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
