#!/usr/bin/env python3
"""
FTFuzz Seed Bucket Loader v2 — maps queue seeds to policy groups via .ftstate.json.

Loads policy_store_v2.json, scans queue seeds/sidecars, builds per-policy-group
buckets keyed by canonical state_class for byte-window inference.

Supports:
  - state_id -> transition_id via state_map.csv
  - direct transition_id keys in sidecar
  - canonical state class normalization

Usage:
  python3 field_inference/seed_bucket_loader.py \\
      --policy-store policy_store_v2.json \\
      --queue-dir /path/to/queue \\
      --state-map state_map_auto.csv \\
      --output policy_group_seed_buckets.real.json \\
      --max-seeds-per-bucket 50
"""

import argparse, csv, json, os, sys
from collections import defaultdict

CANONICAL_CLASSES = [
    'Fail-Pre', 'Reach-Pre', 'Blocked-at-Barrier',
    'Barrier-Reached', 'Progressed-Through-Barrier',
    'Reach-Post', 'Invalid-Post-Without-Pre',
]
ALIASES = {
    'near-post': 'Barrier-Reached', 'nearpost': 'Barrier-Reached',
    'blocked': 'Blocked-at-Barrier', 'blocked_at_barrier': 'Blocked-at-Barrier',
    'reach_pre': 'Reach-Pre', 'reach_post': 'Reach-Post',
    'fail_pre': 'Fail-Pre', 'failpre': 'Fail-Pre',
    'invalid_post_without_pre': 'Invalid-Post-Without-Pre',
    'progressed_through_barrier': 'Progressed-Through-Barrier',
    'post_reached': 'Reach-Post', 'unknown': 'Fail-Pre',
}
CLASS_RANK = {
    'Fail-Pre': 0, 'Invalid-Post-Without-Pre': 0,
    'Reach-Pre': 1,
    'Barrier-Reached': 2, 'Near-Post': 2,
    'Blocked-at-Barrier': 3,
    'Progressed-Through-Barrier': 4, 'Reach-Post': 5,
}


def _normalize(sc):
    if not sc: return 'Fail-Pre'
    key = sc.lower().replace('_', '-').replace(' ', '-')
    return ALIASES.get(key, sc)


def load_state_map(path):
    state_to_tid = {}
    if not path or not os.path.exists(path):
        return state_to_tid
    with open(path) as f:
        for row in csv.DictReader(f):
            sid = int(row['state_id'])
            if sid not in state_to_tid:
                state_to_tid[sid] = row['transition_id']
    return state_to_tid


def load_policy_store(path):
    with open(path) as f:
        text = f.read()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(text)
    return obj


def load_seeds(queue_dir, state_to_tid, ps, max_seeds_per_bucket):
    """Scan queue directory, bucket seeds by policy group + state class."""
    t2pg = ps.get('transition_to_policy_group', {})
    pg_meta = {}
    for gid, g in ps.get('policy_groups', {}).items():
        pg_meta[gid] = {
            'member_transitions': set(g.get('member_transitions', [])),
        }

    buckets = {gid: defaultdict(list) for gid in pg_meta}
    diagnostics = {
        'sidecars_parsed': 0, 'sidecars_unmapped': 0,
        'state_id_mapped': 0, 'transition_id_direct': 0,
        'policy_group_mapped': 0,
    }

    seed_files = [f for f in os.listdir(queue_dir)
                  if f.startswith('id:') and not f.endswith(('.ftstate.json', '.state'))]

    for seed_name in seed_files:
        seed_path = os.path.join(queue_dir, seed_name)
        sidecar_path = seed_path + '.ftstate.json'
        if not os.path.exists(sidecar_path):
            diagnostics['sidecars_unmapped'] += 1
            continue

        diagnostics['sidecars_parsed'] += 1
        try:
            with open(sidecar_path) as f:
                sc = json.load(f)
        except (json.JSONDecodeError, IOError):
            diagnostics['sidecars_unmapped'] += 1
            continue

        seed_bytes = None
        try:
            with open(seed_path, 'rb') as f:
                seed_bytes = f.read()
        except IOError:
            pass

        transitions = sc.get('transitions', {})
        pg_best_class = {}  # gid -> (class, rank, tid)

        for sid_str, info in transitions.items():
            # Try state_id -> transition_id
            sid = int(sid_str)
            tid = state_to_tid.get(sid, sid_str)
            if not tid or tid == sid_str:
                diagnostics['sidecars_unmapped'] += 1
                continue
            if tid != sid_str:
                diagnostics['state_id_mapped'] += 1
            else:
                diagnostics['transition_id_direct'] += 1

            gid = t2pg.get(tid, '')
            if not gid:
                continue

            diagnostics['policy_group_mapped'] += 1
            sc_raw = info.get('state_class', 'Fail-Pre')
            sc = _normalize(sc_raw)
            rank = CLASS_RANK.get(sc, 0)

            if gid not in pg_best_class or rank > pg_best_class[gid][1]:
                pg_best_class[gid] = (sc, rank, tid)

        # Assign seed to each PG's bucket
        for gid in pg_meta:
            if gid in pg_best_class:
                sc, _, tid = pg_best_class[gid]
            else:
                sc = 'Fail-Pre'
                tid = ''

            bucket = buckets[gid][sc]
            if len(bucket) < max_seeds_per_bucket:
                bucket.append({
                    'seed_path': seed_path,
                    'seed_name': seed_name,
                    'sidecar_path': sidecar_path,
                    'transition_id': tid,
                    'state_class': sc,
                    'min_distance': sc.get('min_distance', 0) if isinstance(sc, dict) else 0,
                    'size': len(seed_bytes) if seed_bytes else 0,
                })

    return buckets, diagnostics


def main():
    p = argparse.ArgumentParser(description='Seed Bucket Loader v2')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--queue-dir', required=True)
    p.add_argument('--state-map', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--max-seeds-per-bucket', type=int, default=50)
    args = p.parse_args()

    ps = load_policy_store(args.policy_store)
    state_to_tid = load_state_map(args.state_map)
    buckets, diag = load_seeds(args.queue_dir, state_to_tid, ps, args.max_seeds_per_bucket)

    # Build output
    pg_out = {}
    for gid in buckets:
        pg_out[gid] = {cls: buckets[gid].get(cls, []) for cls in CANONICAL_CLASSES}

    output = {
        'schema_version': 'ftfuzz.policy_group_seed_buckets.v1',
        'synthetic': False,
        'policy_groups': pg_out,
        'diagnostics': diag,
    }

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f'Wrote {args.output}')

    for gid in pg_out:
        counts = {k: len(v) for k, v in pg_out[gid].items() if len(v) > 0}
        print(f'  {gid}: {counts}' if counts else f'  {gid}: (empty)')
    print(f'Diagnostics: {json.dumps(diag)}')


if __name__ == '__main__':
    main()
