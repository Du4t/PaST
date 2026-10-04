#!/usr/bin/env python3
"""
FTFuzz Policy Validator — validates semantic_policies.json against schema.

Usage:
  python3 policy/policy_validator.py semantic_policies.json
"""

import argparse
import json
import sys


def validate_semantic_policies(data):
    """Validate semantic_policies.json structure. Returns (ok, errors)."""
    errors = []

    if data.get('schema_version') != 'ftfuzz.semantic_mutation_policy.v1':
        errors.append('Invalid or missing schema_version')

    policies = data.get('policies', {})
    if not policies:
        errors.append('No policies found')

    for tid, p in policies.items():
        # Required fields
        for field in ['transition_id', 'enabled', 'policy_version',
                      'policy_type', 'mutation_actions']:
            if field not in p:
                errors.append(f'{tid}: missing {field}')

        ma = p.get('mutation_actions', {})
        for field in ['preserve_hints', 'focus_hints', 'dictionary_tokens',
                      'numeric_hints', 'operator_weights']:
            if field not in ma:
                errors.append(f'{tid}: mutation_actions missing {field}')

        # Confidence range
        conf = p.get('confidence', -1)
        if conf < 0 or conf > 1:
            errors.append(f'{tid}: confidence out of range ({conf})')

        # Dictionary token format
        for t in ma.get('dictionary_tokens', []):
            if 'token' not in t:
                errors.append(f'{tid}: dictionary_token missing token')
            if t.get('source', '') not in ('llm_semantics', 'rule_extractor',
                                           'format_heuristic'):
                errors.append(f'{tid}: invalid token source: {t.get("source")}')

    return len(errors) == 0, errors


def validate_policy_store(data):
    """Validate policy_store.json structure. Supports v1 and v2."""
    errors = []
    sv = data.get('schema_version', '')

    if sv == 'ftfuzz.policy_store.v2':
        return validate_policy_store_v2(data)
    elif sv == 'ftfuzz.policy_store.v1':
        return validate_policy_store_v1(data)
    else:
        errors.append(f'Unknown schema_version: {sv}')
        return False, errors


def validate_policy_store_v2(data):
    """Validate v2 policy store."""
    errors = []

    if data.get('activation_mode') != 'seed_state_conditioned':
        errors.append('activation_mode must be seed_state_conditioned')
    if 'store_version' not in data:
        errors.append('Missing store_version')
    if 'policy_groups' not in data:
        errors.append('Missing policy_groups')
    if 'transition_to_policy_group' not in data:
        errors.append('Missing transition_to_policy_group')

    for gid, g in data.get('policy_groups', {}).items():
        for field in ['enabled', 'priority', 'representative_transition',
                       'member_transitions', 'mutation_actions']:
            if field not in g:
                errors.append(f'{gid}: missing {field}')
        ma = g.get('mutation_actions', {})
        if 'dictionary_tokens' not in ma:
            errors.append(f'{gid}: missing dictionary_tokens')
        if 'operator_weights' not in ma:
            errors.append(f'{gid}: missing operator_weights')

    # Check mappings point to existing groups
    pg_ids = set(data.get('policy_groups', {}).keys())
    for tid, gid in data.get('transition_to_policy_group', {}).items():
        if gid not in pg_ids:
            errors.append(f'{tid} maps to non-existent group {gid}')

    return len(errors) == 0, errors


def validate_policy_store_v1(data):
    """Validate v1 policy store."""
    errors = []

    if 'store_version' not in data:
        errors.append('Missing store_version')
    if 'active_transition' not in data:
        errors.append('Missing active_transition')
    if 'policies' not in data:
        errors.append('Missing policies')

    for tid, p in data.get('policies', {}).items():
        for field in ['transition_id', 'policy_version', 'enabled',
                      'mutation_actions']:
            if field not in p:
                errors.append(f'{tid}: missing {field}')
        ma = p.get('mutation_actions', {})
        if 'dictionary_tokens' not in ma:
            errors.append(f'{tid}: missing dictionary_tokens')
        if 'operator_weights' not in ma:
            errors.append(f'{tid}: missing operator_weights')

    return len(errors) == 0, errors


def main():
    parser = argparse.ArgumentParser(description='FTFuzz Policy Validator')
    parser.add_argument('path', help='Path to semantic_policies.json or policy_store.json')
    parser.add_argument('--type', choices=['semantic', 'store'],
                        default='semantic', help='Policy type to validate')
    args = parser.parse_args()

    with open(args.path) as f:
        data = json.load(f)

    if args.type == 'store':
        ok, errors = validate_policy_store(data)
    else:
        ok, errors = validate_semantic_policies(data)

    if ok:
        print('PASS')
    else:
        print(f'FAIL: {len(errors)} error(s)')
        for e in errors:
            print(f'  - {e}')

    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
