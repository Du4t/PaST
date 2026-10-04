#!/usr/bin/env python3
"""
Validates byte-window inference: checks that real (non-synthetic) ranges
are produced from seed buckets and grounded into policy_store.

Usage:
  python3 field_inference/validate_byte_window_inference.py \\
      --alignment-report seed_bucket_alignment_report.json \\
      --seed-buckets policy_group_seed_buckets.real.json \\
      --byte-windows byte_windows.real.json \\
      --grounded-store grounded_policy_store_v2.real.json \\
      --mutator-log mutator.log \\
      --out byte_window_inference_validation.json
"""

import argparse, json, os, re, sys


def _has_blocked_like(ar):
    if not ar: return False
    for g in ar.get('policy_groups', {}).values():
        dist = g.get('seed_distribution', {})
        for k in ['Blocked-at-Barrier', 'Barrier-Reached', 'Near-Post']:
            if dist.get(k, 0) > 0:
                return True
    return False


def validate(args):
    checks = {}
    stats = {}
    errors = []

    # 1. Alignment report
    ar = None
    if os.path.exists(args.alignment_report):
        with open(args.alignment_report) as f:
            ar = json.load(f)
    checks['alignment_report_exists'] = ar is not None
    if ar:
        summary = ar.get('summary', {})
        checks['real_reach_pre_bucket_gt_0'] = any(
            g.get('seed_distribution', {}).get('Reach-Pre', 0) > 0
            for g in ar.get('policy_groups', {}).values())
        checks['real_blocked_bucket_gt_0'] = _has_blocked_like(ar)
        stats['alignment_status'] = summary.get('alignment_status', 'unknown')
        stats['sidecars_with_pg'] = summary.get('sidecars_with_policy_group', 0)

    # 2. Seed buckets
    sb = None
    if os.path.exists(args.seed_buckets):
        with open(args.seed_buckets) as f:
            sb = json.load(f)
    checks['seed_buckets_real_exists'] = sb is not None
    checks['seed_buckets_synthetic_false'] = (
        sb is not None and sb.get('synthetic', True) is False)
    if sb:
        for gid, bg in sb.get('policy_groups', {}).items():
            for cls in ['Reach-Pre', 'Blocked-at-Barrier', 'Barrier-Reached']:
                cnt = len(bg.get(cls, []))
                stats[f'{gid}_{cls}'] = cnt

    # 3. Byte windows
    bw = None
    if os.path.exists(args.byte_windows):
        with open(args.byte_windows) as f:
            bw = json.load(f)
    checks['byte_windows_real_exists'] = bw is not None
    checks['byte_windows_synthetic_false'] = (
        bw is not None and bw.get('synthetic', True) is False)
    if bw:
        real_focus = 0
        real_preserve = 0
        for gid, g in bw.get('policy_groups', {}).items():
            for r in g.get('focus_ranges', []):
                if not r.get('synthetic', True):
                    real_focus += 1
            for r in g.get('preserve_ranges', []):
                if not r.get('synthetic', True):
                    real_preserve += 1
        stats['real_focus_ranges'] = real_focus
        stats['real_preserve_ranges'] = real_preserve
        checks['real_focus_range_gt_0'] = real_focus > 0

    # 4. Grounded store
    gs = None
    if os.path.exists(args.grounded_store):
        with open(args.grounded_store) as f:
            gs = json.load(f)
    checks['grounded_store_real_exists'] = gs is not None
    if gs:
        meta = gs.get('metadata', {})
        checks['grounded_store_synthetic_false'] = meta.get('synthetic', True) is False
        checks['grounded_metadata_grounded_true'] = meta.get('grounded', False) is True
        stats['grounded_store_version'] = gs.get('store_version', 0)
        gr = sum(1 for g in gs.get('policy_groups', {}).values()
                 if g.get('mutation_actions', {}).get('focus_ranges')
                 or g.get('mutation_actions', {}).get('preserve_ranges'))
        stats['grounded_groups_with_ranges'] = gr

    # 5. Mutator log
    log_text = ''
    if args.mutator_log and os.path.exists(args.mutator_log):
        with open(args.mutator_log) as f:
            log_text = f.read()
    checks['mutator_range_log_present'] = bool(re.search(r'\[RANGE\]', log_text))
    checks['real_range_mutation_present'] = bool(
        re.search(r'insert_focus|focus_havoc|preserve_aware', log_text))
    checks['no_crash'] = not bool(re.search(
        r'segfault|SIGSEGV|SIGABRT|assertion', log_text, re.IGNORECASE))

    valid = all([
        checks.get('alignment_report_exists', False),
        checks.get('byte_windows_synthetic_false', False),
        checks.get('grounded_store_synthetic_false', False),
        checks.get('real_focus_range_gt_0', False),
        checks.get('no_crash', False),
    ])

    return {'valid': valid, 'checks': checks, 'stats': stats, 'errors': errors}


def main():
    p = argparse.ArgumentParser(description='Byte Window Inference Validator')
    p.add_argument('--alignment-report', required=True)
    p.add_argument('--seed-buckets', required=True)
    p.add_argument('--byte-windows', required=True)
    p.add_argument('--grounded-store', required=True)
    p.add_argument('--mutator-log', default=None)
    p.add_argument('--out', default=None)
    args = p.parse_args()

    result = validate(args)
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(result, f, indent=2)

    status = 'PASS' if result['valid'] else 'FAIL'
    print(f'{status} ({sum(result["checks"].values())}/{len(result["checks"])} checks)')
    for k, v in sorted(result['checks'].items()):
        print(f'  [{"OK" if v else "FAIL"}] {k}')
    for k, v in sorted(result['stats'].items()):
        print(f'  {k}: {v}')
    sys.exit(0 if result['valid'] else 1)


if __name__ == '__main__':
    main()
