#!/usr/bin/env python3
"""
FTFuzz Action DSL Compiler (Stage: LLM Action DSL)

Validates LLM-produced Action DSL plans. Compiler only does:
  1. Schema validation
  2. Opcode validity check
  3. Parameter completeness check
  4. Fallback path existence check
  5. Forbidden action detection

Compiler does NOT:
  - Add semantics (e.g., wrap xml:id= in quotes)
  - Synthesize fallback paths
  - Downgrade incomplete tokens to random insertions

Usage:
  python3 policy/action_dsl_compiler.py \
      --llm-output llm_action_plan.json \
      --out compiled_action_plan.json \
      --report compilation_report.json
"""

import argparse, json, os, sys
from policy.action_dsl_ops import (
    ALL_DSL_OPS, RAW_TOKEN_OPS, MVP_IMPLEMENTED,
    FORBIDDEN_FOR_INTERNAL_TABLE, get_params, is_raw_token_op,
)

INCOMPLETE_TOKEN_SUFFIXES = ['=', ':"', ":='", '="', "='", ':']


def validate_dsl(llm_output):
    """Validate LLM Action DSL output. Returns (valid, errors, warnings, report)."""
    errors = []
    warnings = []
    report = {
        'schema_version': 'ftfuzz.action_compilation_report.v1',
        'compiler_added_semantics': False,
        'accepted_actions': [],
        'rejected_actions': [],
        'non_executable_reasons': [],
    }

    # Check top-level fields
    if llm_output.get('schema_version') != 'ftfuzz.llm_action_dsl.v1':
        errors.append("Invalid or missing schema_version")
        return False, errors, warnings, report

    tid = llm_output.get('transition_id', '?')
    report['transition_id'] = tid
    report['barrier_condition'] = llm_output.get('barrier_condition', 'unknown')

    # Check state_goal
    state_goal = llm_output.get('state_goal', {})
    goal_kind = state_goal.get('kind', '')
    if not goal_kind:
        errors.append("Missing state_goal.kind")

    # Determine if this is an internal_table barrier
    is_internal_table = goal_kind in ('materialize_internal_table', 'internal_table_materialization')

    # Check mechanisms
    mechanisms = llm_output.get('mechanisms', [])
    if not mechanisms:
        errors.append("No mechanisms provided")
        return False, errors, warnings, report

    for mech in mechanisms:
        mid = mech.get('mechanism_id', '?')
        mech_ok = True

        # Required fields per mechanism
        for field in ['mechanism_id', 'name', 'primary_path']:
            if not mech.get(field):
                errors.append(f"[{mid}] Missing required field: {field}")
                mech_ok = False

        # Fallback construction path
        fallback = mech.get('fallback_construction_path', [])
        if not fallback:
            if is_internal_table:
                errors.append(f"[{mid}] Missing fallback_construction_path (required for internal_table barrier)")
                mech_ok = False
            else:
                warnings.append(f"[{mid}] No fallback_construction_path")

        # Validate primary_path
        primary = mech.get('primary_path', [])
        if primary:
            mech_ok &= validate_action_steps(primary, is_internal_table, mid, 'primary', errors, warnings, report)
        else:
            errors.append(f"[{mid}] primary_path is empty")
            mech_ok = False

        # Validate fallback_construction_path
        if fallback:
            validate_action_steps(fallback, is_internal_table, mid, 'fallback', errors, warnings, report)

        # Validate forbidden_actions
        forbidden = mech.get('forbidden_actions', []) + llm_output.get('forbidden_actions', [])
        for fa in forbidden:
            op = fa.get('op', '')
            if is_raw_token_op(op):
                report['accepted_actions'].append({
                    'mechanism_id': mid, 'type': 'forbidden_action_declared',
                    'op': op, 'token': fa.get('token', ''),
                    'reason': fa.get('reason', ''),
                })

        if mech_ok:
            report['accepted_actions'].append({
                'mechanism_id': mid, 'type': 'mechanism_accepted',
                'name': mech.get('name', ''),
                'primary_steps': len(primary),
                'fallback_steps': len(fallback),
            })
        else:
            report['rejected_actions'].append({
                'mechanism_id': mid, 'type': 'mechanism_rejected',
                'reasons': [e for e in errors if f'[{mid}]' in e],
            })

    valid = len(errors) == 0
    if not valid:
        report['non_executable_reasons'] = errors

    return valid, errors, warnings, report


def validate_action_steps(steps, is_internal_table, mid, path_label, errors, warnings, report):
    """Validate a list of action steps."""
    all_ok = True
    for i, step in enumerate(steps):
        op = step.get('op', '')
        step_id = f"{mid}/{path_label}[{i}]"

        # 1. Opcode in allowed set
        if op not in ALL_DSL_OPS:
            errors.append(f"[{step_id}] Unknown opcode: {op}")
            all_ok = False
            continue

        # 2. Raw token ops forbidden for internal_table
        if is_internal_table and op in FORBIDDEN_FOR_INTERNAL_TABLE:
            tok = step.get('params', {}).get('token', '')
            errors.append(f"[{step_id}] {op} forbidden for internal_table barrier (token={tok})")
            reject = {'step_id': step_id, 'op': op, 'token': tok,
                      'reason': f'{op} forbidden for internal_table materialization'}
            if reject not in report['rejected_actions']:
                report['rejected_actions'].append(reject)
            all_ok = False
            continue

        # 3. Incomplete token detection
        if op == 'INSERT_TOKEN_IN_REGION':
            params = step.get('params', {})
            token = params.get('token', '')
            for suffix in INCOMPLETE_TOKEN_SUFFIXES:
                if token.endswith(suffix):
                    errors.append(
                        f"[{step_id}] Incomplete token '{token}': "
                        f"ends with '{suffix}'. Must provide complete literal_format.")
                    all_ok = False
                    break

        # 4. INSERT_ATTRIBUTE must have literal_format containing {value}
        if op == 'INSERT_ATTRIBUTE':
            params = step.get('params', {})
            lit = params.get('literal_format', '')
            if '{value}' not in lit and '{attr_value_ref}' not in str(step):
                errors.append(f"[{step_id}] INSERT_ATTRIBUTE missing {{value}} in literal_format")
                all_ok = False

        # 5. INSERT_ELEMENT_PAIR_WITH_FIELD must have literal_format containing {element} and {value}
        if op == 'INSERT_ELEMENT_PAIR_WITH_FIELD':
            params = step.get('params', {})
            lit = params.get('literal_format', '')
            if '{element}' not in lit and '{value}' not in lit:
                errors.append(f"[{step_id}] INSERT_ELEMENT_PAIR_WITH_FIELD missing templates in literal_format")
                all_ok = False

        # 6. Parameter check
        req_params, opt_params = get_params(op)
        params = step.get('params', {})
        for rp in req_params:
            if rp not in params:
                errors.append(f"[{step_id}] Missing required param '{rp}' for {op}")
                all_ok = False

        # 7. on_fail check
        has_on_fail = 'on_fail' in step or 'on_success' in step
        if not has_on_fail:
            warnings.append(f"[{step_id}] {op} has no on_fail/on_success branch")

        # 8. MVP check
        if op not in MVP_IMPLEMENTED:
            warnings.append(f"[{step_id}] {op} not in MVP implemented set (will fail at runtime)")

    return all_ok


def main():
    p = argparse.ArgumentParser(description='Action DSL Compiler')
    p.add_argument('--llm-output', required=True, help='LLM Action DSL JSON')
    p.add_argument('--out', default='compiled_action_plan.json')
    p.add_argument('--report', default='action_compilation_report.json')
    args = p.parse_args()

    with open(args.llm_output, 'r') as f:
        llm_output = json.load(f)

    valid, errors, warnings, report = validate_dsl(llm_output)

    # Always set compiler_added_semantics=false
    report['compiler_added_semantics'] = False

    for path in [args.out, args.report]:
        d = os.path.dirname(path)
        if d: os.makedirs(d, exist_ok=True)

    output = {
        'valid': valid,
        'compiler_added_semantics': False,
        'transition_id': report['transition_id'],
        'accepted_mechanisms': [a for a in report['accepted_actions'] if a.get('type') == 'mechanism_accepted'],
        'rejected': report['rejected_actions'],
        'non_executable_reasons': report.get('non_executable_reasons', []),
    }
    with open(args.out, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"[OUTPUT] {args.out}")

    with open(args.report, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[REPORT] {args.report}")

    print(f'\n{"="*60}')
    print(f'DSL COMPILATION: {"PASS" if valid else "FAIL"}')
    print(f'  Accepted mechanisms: {len(output["accepted_mechanisms"])}')
    print(f'  Rejected: {len(report["rejected_actions"])}')
    print(f'  Compiler added semantics: FALSE')
    for e in errors:
        print(f'  [ERROR] {e}')
    for w in warnings[:5]:
        print(f'  [WARN] {w}')

    sys.exit(0 if valid else 1)


if __name__ == '__main__':
    main()
