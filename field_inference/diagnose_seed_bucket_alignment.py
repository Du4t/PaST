#!/usr/bin/env python3
"""
Diagnose seed bucket alignment — identifies why policy group member transitions
don't align with .ftstate.json sidecar data.

Usage:
  python3 field_inference/diagnose_seed_bucket_alignment.py \\
      --policy-store policy_store_v2.json \\
      --state-map state_map_auto.csv \\
      --queue-dir /path/to/queue \\
      --out seed_bucket_alignment_report.json
"""

import argparse, csv, json, os, sys
from collections import Counter, defaultdict


def load_json(path):
    with open(path) as f:
        text = f.read()
    try: return json.loads(text)
    except json.JSONDecodeError:
        return json.JSONDecoder().raw_decode(text)[0]


def main():
    p = argparse.ArgumentParser(description='Diagnose Seed Bucket Alignment')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--state-map', required=True)
    p.add_argument('--queue-dir', required=True)
    p.add_argument('--out', required=True)
    args = p.parse_args()

    # Load state_map
    state_to_tid = {}
    tid_to_sids = defaultdict(dict)
    with open(args.state_map) as f:
        for row in csv.DictReader(f):
            sid = int(row['state_id'])
            tid = row['transition_id']
            role = row['role']
            if sid not in state_to_tid: state_to_tid[sid] = tid
            tid_to_sids[tid][role] = sid

    # Load policy store
    ps = load_json(args.policy_store)
    t2pg = ps.get('transition_to_policy_group', {})
    pg_data = {}

    # Scan sidecars
    sidecar_files = sorted(
        [f for f in os.listdir(args.queue_dir) if f.endswith('.ftstate.json')])
    errors = []
    warnings = []

    # Per-PG state class distribution
    pg_dist = defaultdict(lambda: defaultdict(int))
    sidecar_stats = {
        'total': len(sidecar_files),
        'parsed': 0, 'parse_failed': 0,
        'with_mapped_transition': 0,
        'with_policy_group': 0,
    }

    # Global transition counts
    tid_sidecar_hits = Counter()
    all_state_classes = Counter()

    for sc_name in sidecar_files:
        sc_path = os.path.join(args.queue_dir, sc_name)
        try:
            with open(sc_path) as f:
                sc = json.load(f)
            sidecar_stats['parsed'] += 1
        except Exception:
            sidecar_stats['parse_failed'] += 1
            continue

        transitions = sc.get('transitions', {})
        seed_has_mapped = False
        seed_has_pg = False

        for sid_str, info in transitions.items():
            sid = int(sid_str)
            tid = state_to_tid.get(sid, '')
            if not tid:
                continue

            tid_sidecar_hits[tid] += 1
            sc_name_raw = info.get('state_class', 'Fail-Pre')
            all_state_classes[sc_name_raw] += 1
            seed_has_mapped = True

            gid = t2pg.get(tid, '')
            if not gid:
                continue

            seed_has_pg = True
            pg_dist[gid][sc_name_raw] += 1

        if seed_has_mapped:
            sidecar_stats['with_mapped_transition'] += 1
        if seed_has_pg:
            sidecar_stats['with_policy_group'] += 1

    # Per-PG member transition analysis
    for gid, g in ps.get('policy_groups', {}).items():
        members = g.get('member_transitions', [])
        mt_info = {}
        for mt in members:
            sids = tid_to_sids.get(mt, {})
            hits = tid_sidecar_hits.get(mt, 0)
            mt_info[mt] = {
                'in_state_map': mt in tid_to_sids,
                'state_ids': sids,
                'in_t2pg': mt in t2pg,
                'sidecar_hits': hits,
            }
            if not mt in tid_to_sids:
                warnings.append(f'{mt} not in state_map')
            if hits == 0:
                warnings.append(f'{mt} has 0 sidecar hits in {len(sidecar_files)} sidecars')

        pg_data[gid] = {
            'member_transitions': members,
            'member_transition_status': mt_info,
            'seed_distribution': dict(pg_dist.get(gid, {})),
        }

    # Summary
    member_count = sum(len(g['member_transitions']) for g in ps.get('policy_groups', {}).values())
    in_map = sum(1 for g in pg_data.values()
                 for mt in g['member_transition_status'].values()
                 if mt['in_state_map'])
    missing_map = member_count - in_map

    alignment = 'failed'
    if sidecar_stats['with_policy_group'] > 0:
        alignment = 'partial'
    if sidecar_stats['with_policy_group'] > sidecar_stats['total'] * 0.1:
        alignment = 'ok'

    if sidecar_stats['with_policy_group'] == 0:
        errors.append('NO sidecar has a transition mapped to any policy group')
        errors.append('Root cause: transition_to_policy_group maps do not match sidecar transition IDs')
        errors.append('Check: state_map state_id -> transition_id mapping matches member_transitions')

    report = {
        'schema_version': 'ftfuzz.seed_bucket_alignment_report.v1',
        'summary': {
            'policy_group_count': len(ps.get('policy_groups', {})),
            'member_transition_count': member_count,
            'member_transitions_in_state_map': in_map,
            'member_transitions_missing_state_map': missing_map,
            'sidecar_count': sidecar_stats['total'],
            'sidecars_parsed': sidecar_stats['parsed'],
            'sidecars_with_mapped_transition': sidecar_stats['with_mapped_transition'],
            'sidecars_with_policy_group': sidecar_stats['with_policy_group'],
            'alignment_status': alignment,
        },
        'policy_groups': pg_data,
        'top_sidecar_transitions': tid_sidecar_hits.most_common(10),
        'all_state_classes': dict(all_state_classes.most_common()),
        'errors': errors,
        'warnings': warnings,
    }

    with open(args.out, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f'Alignment: {alignment}')
    print(f'Sidecars: {sidecar_stats["total"]} total, {sidecar_stats["with_policy_group"]} with PG')
    print(f'Member transitions: {member_count} total, {missing_map} missing from state_map')
    for gid, data in pg_data.items():
        dist = data['seed_distribution']
        print(f'  {gid}: {dict(dist)}')
    for e in errors:
        print(f'  ERROR: {e}')
    for w in warnings[:5]:
        print(f'  WARN: {w}')


if __name__ == '__main__':
    main()
