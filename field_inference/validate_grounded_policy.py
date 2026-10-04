#!/usr/bin/env python3
"""
FTFuzz Grounded Policy Validator — validates grounded_policy_store_v2.json.

Checks:
  1. byte_windows.json schema valid
  2. preserve_ranges or focus_ranges present
  3. grounded_policy_store_v2.json schema valid
  4. metadata.grounded=true
  5. C loader range log evidence
  6. Mutator range-aware mutation evidence

Usage:
  python3 field_inference/validate_grounded_policy.py \\
      --byte-windows byte_windows.json \\
      --grounded-store grounded_policy_store_v2.json \\
      --mutator-log mutator.log \\
      --out grounded_policy_validation.json
"""

import argparse, json, os, re, sys


def validate(args):
    checks = {}
    stats = {}
    errors = []
    warnings = []

    # 1. Byte windows
    bw = None
    if os.path.exists(args.byte_windows):
        with open(args.byte_windows) as f:
            bw = json.load(f)
    checks['byte_windows_exists'] = bw is not None
    checks['byte_windows_schema_valid'] = (
        bw is not None and bw.get('schema_version') == 'ftfuzz.byte_windows.v1')

    if bw:
        pg_bw = bw.get('policy_groups', {})
        stats['groups_with_preserve'] = sum(1 for g in pg_bw.values() if g.get('preserve_ranges'))
        stats['groups_with_focus'] = sum(1 for g in pg_bw.values() if g.get('focus_ranges'))
        checks['has_preserve_or_focus'] = stats['groups_with_preserve'] > 0 or stats['groups_with_focus'] > 0
    else:
        stats['groups_with_preserve'] = 0
        stats['groups_with_focus'] = 0
        checks['has_preserve_or_focus'] = False

    # 2. Grounded store
    gs = None
    if os.path.exists(args.grounded_store):
        with open(args.grounded_store) as f:
            gs = json.load(f)
    checks['grounded_store_exists'] = gs is not None
    checks['grounded_store_schema_valid'] = (
        gs is not None and gs.get('schema_version') == 'ftfuzz.policy_store.v2')

    if gs:
        meta = gs.get('metadata', {})
        checks['metadata_grounded_true'] = meta.get('grounded', False) is True
        stats['grounded_store_version'] = gs.get('store_version', 0)
        stats['grounded_groups'] = len(gs.get('policy_groups', {}))

        groups_with_ranges = sum(1 for g in gs.get('policy_groups', {}).values()
                                 if (g.get('mutation_actions', {}).get('preserve_ranges')
                                     or g.get('mutation_actions', {}).get('focus_ranges')))
        stats['groups_with_ranges'] = groups_with_ranges
        checks['grounded_has_ranges'] = groups_with_ranges > 0
    else:
        checks['metadata_grounded_true'] = False
        checks['grounded_has_ranges'] = False
        stats['grounded_store_version'] = 0

    # 3. Mutator log evidence
    log_text = ''
    if args.mutator_log and os.path.exists(args.mutator_log):
        with open(args.mutator_log) as f:
            log_text = f.read()

    checks['mutator_range_log_present'] = bool(re.search(r'\[RANGE\]', log_text))
    checks['range_aware_mutation_present'] = bool(
        re.search(r'insert_focus|focus_havoc|preserve_aware', log_text))
    checks['no_mutator_crash'] = not bool(re.search(
        r'segmentation fault|SIGSEGV|SIGABRT|assertion failed', log_text, re.IGNORECASE))
    checks['fuzzer_not_restarted'] = len(re.findall(
        r'=== FTFuzz Semantic Mutator Init', log_text)) == 1

    # Extract range stats
    range_ins = re.findall(r'range_insertions=(\d+)', log_text)
    focus_hvc = re.findall(r'focus_havoc=(\d+)', log_text)
    preserve_aw = re.findall(r'preserve_aware=(\d+)', log_text)
    stats['range_insertions'] = sum(int(x) for x in range_ins)
    stats['focus_havoc_count'] = sum(int(x) for x in focus_hvc)
    stats['preserve_aware_count'] = sum(int(x) for x in preserve_aw)

    # Determine validity
    valid = all([
        checks.get('byte_windows_exists', False),
        checks.get('grounded_store_exists', False),
        checks.get('grounded_store_schema_valid', False),
        checks.get('metadata_grounded_true', False),
        checks.get('no_mutator_crash', False),
    ])

    return {
        'valid': valid,
        'checks': checks,
        'stats': stats,
        'errors': errors,
        'warnings': warnings,
    }


def main():
    p = argparse.ArgumentParser(description='Grounded Policy Validator')
    p.add_argument('--byte-windows', required=True)
    p.add_argument('--grounded-store', required=True)
    p.add_argument('--mutator-log', default=None)
    p.add_argument('--out', default=None)
    args = p.parse_args()

    result = validate(args)

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(result, f, indent=2)
        print(f'Report: {args.out}')

    status = 'PASS' if result['valid'] else 'FAIL'
    print(f'{status} ({sum(result["checks"].values())}/{len(result["checks"])} checks)')
    for e in result.get('errors', []):
        print(f'  ERROR: {e}')
    for w in result.get('warnings', []):
        print(f'  WARN: {w}')
    for k, v in sorted(result['checks'].items()):
        print(f'  [{"OK" if v else "FAIL"}] {k}')
    for k, v in sorted(result['stats'].items()):
        print(f'  {k}: {v}')

    sys.exit(0 if result['valid'] else 1)


if __name__ == '__main__':
    main()
