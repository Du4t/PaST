#!/usr/bin/env python3
"""
FTFuzz Seed-State Policy Selector (Stage 2.1-pre)

Given a seed's .ftstate.json and a multi-policy store, selects applicable
policies based on the seed's per-transition state classes.

Usage:
  python3 policy/seed_state_policy_selector.py \
      --sidecar /path/to/id:xxx.ftstate.json \
      --policy-store /path/to/policy_store_v2.json \
      --json
"""

import argparse, json, sys, os


def get_seed_states(sidecar_path):
    """Extract per-transition state classes from .ftstate.json."""
    with open(sidecar_path) as f:
        data = json.load(f)
    states = {}
    for tid, td in data.get('transitions', {}).items():
        states[tid] = td.get('state_class', 'Unknown')
    return states, data


def select_policies(seed_states, policy_store, max_policies=4):
    """Select applicable policies based on seed state classes.

    Returns list of (tid, policy_dict, reason) sorted by priority descending.
    """
    policies = policy_store.get('policies', {})
    selection = policy_store.get('selection_policy', {})
    fallback = selection.get('fallback', 'havoc')
    max_n = selection.get('max_applicable_policies_per_seed', 4)

    applicable = []

    for tid, state_class in seed_states.items():
        if tid not in policies:
            continue
        policy = policies[tid]
        if not policy.get('enabled', False):
            continue

        activation = policy.get('activation', {})
        allowed_classes = activation.get('state_classes', [])

        if state_class in allowed_classes:
            applicable.append((
                policy['priority'],
                tid,
                policy,
                f'seed state_class={state_class} matches activation.state_classes'
            ))
        else:
            applicable.append((
                policy['priority'] * 0.3,  # reduced priority
                tid,
                policy,
                f'state_class={state_class} not in {allowed_classes}, low priority'
            ))

    # Sort by priority descending
    applicable.sort(key=lambda x: -x[0])

    selected = []
    for priority, tid, policy, reason in applicable[:max_n]:
        selected.append({
            'transition_id': tid,
            'priority': priority,
            'policy': policy,
            'reason': reason,
        })

    if not selected:
        return [], fallback

    return selected, fallback


def main():
    parser = argparse.ArgumentParser(
        description='FTFuzz Seed-State Policy Selector')
    parser.add_argument('--sidecar', required=True,
                        help='Path to .ftstate.json sidecar')
    parser.add_argument('--policy-store', required=True,
                        help='Path to policy_store_v2.json')
    parser.add_argument('--json', action='store_true',
                        help='Output JSON')
    parser.add_argument('--max-policies', type=int, default=4)
    args = parser.parse_args()

    states, _ = get_seed_states(args.sidecar)
    with open(args.policy_store) as f:
        store = json.load(f)

    selected, fallback = select_policies(states, store, args.max_policies)

    if args.json:
        result = {
            'seed': os.path.basename(args.sidecar),
            'states': states,
            'activation_mode': store.get('activation_mode', 'unknown'),
            'applicable_policies': [
                {
                    'transition_id': s['transition_id'],
                    'priority': round(s['priority'], 4),
                    'semantic_source': s['policy'].get('semantic_source', '?'),
                    'tokens': len(s['policy'].get('mutation_actions', {}).get(
                        'dictionary_tokens', [])),
                    'reason': s['reason'],
                }
                for s in selected
            ],
            'selected_count': len(selected),
            'fallback': fallback,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f'Seed: {args.sidecar}')
        print(f'Activation: {store.get("activation_mode", "unknown")}')
        print(f'States: {states}')
        print(f'Selected ({len(selected)}):')
        for s in selected:
            tokens = len(s['policy'].get('mutation_actions', {}).get(
                'dictionary_tokens', []))
            print(f'  {s["transition_id"]} pri={s["priority"]:.2f} '
                  f'tokens={tokens}: {s["reason"]}')
        if not selected:
            print(f'  FALLBACK: {fallback}')


if __name__ == '__main__':
    main()
