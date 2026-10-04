#!/usr/bin/env python3
"""
Ontology-to-Action Policy Compiler (Stage 2.3-fix D+E)

Lowers ontology atoms to generic mutator actions with:
  - Action classification (active_mutation / passive_constraint / reject)
  - 5-level grounding system
  - Fallback chains

Usage:
  python3 policy/ontology_policy_compiler.py \
      --atoms ontology_atoms.json \
      --capabilities policy/mutator_capabilities.json \
      --out ontology_action_plan.json \
      --report compilation_report.json
"""

import argparse, json, os, sys
from collections import defaultdict

# --- Lowering table ---
LOWERING_TABLE = {
    'preserve':                  ['PRESERVE_REGION'],
    'remove':                    ['DELETE_REGION'],
    'empty':                     ['EMPTY_REGION'],
    'create':                    ['INSERT_TOKEN_IN_REGION'],
    'make_non_empty':            ['INSERT_TOKEN_IN_REGION'],
    'remove_or_forbid':          ['REMOVE_TOKENS', 'FORBID_TOKENS'],
    'create_or_preserve':        ['INSERT_TOKEN_IN_REGION', 'PRESERVE_REGION'],
    'create_or_keep_non_empty':  ['INSERT_TOKEN_IN_REGION', 'PRESERVE_REGION'],
    'mutate':                    ['FOCUS_RANGE_HAVOC'],
    'move_earlier':              ['MOVE_REGION_EARLIER'],
    'extend_after':              ['EXTEND_AFTER_REGION'],
    'repair_consistency':        ['REJECT_UNSUPPORTED'],
    'unsupported':               ['REJECT_UNSUPPORTED'],
}

# --- Action classification (Fix D) ---
ACTIVE_MUTATION_OPS = {
    'REMOVE_TOKENS', 'DELETE_REGION', 'EMPTY_REGION',
    'INSERT_TOKEN_IN_REGION', 'FOCUS_RANGE_HAVOC',
    'DUPLICATE_REGION', 'MOVE_REGION_EARLIER',
    'EXTEND_AFTER_REGION', 'PRESERVE_AWARE_HAVOC',
}

PASSIVE_CONSTRAINT_OPS = {
    'PRESERVE_REGION', 'FORBID_TOKENS',
}

REJECT_OPS = {'REJECT_UNSUPPORTED'}

def classify_action(op):
    if op in ACTIVE_MUTATION_OPS:
        return 'active_mutation'
    if op in PASSIVE_CONSTRAINT_OPS:
        return 'passive_constraint'
    if op in REJECT_OPS:
        return 'reject'
    return 'active_mutation'  # default new ops to active

# --- Grounding levels (Fix E) ---
# Level 0: none — Reject
# Level 1: token_presence — evidence_tokens non-empty
# Level 2: token_local_boundary — tokens + delimiter/boundary scan
# Level 3: focus_range — focus_range available
# Level 4: focus_range_plus_boundary — range + boundary evidence

OPERATOR_GROUNDING = {
    'REMOVE_TOKENS':       {'min_level': 1},
    'FORBID_TOKENS':       {'min_level': 1},
    'DELETE_REGION':       {'min_level': 2, 'fallback_to': 'REMOVE_TOKENS', 'fallback_min_level': 1},
    'EMPTY_REGION':        {'min_level': 2, 'fallback_to': None},
    'INSERT_TOKEN_IN_REGION': {'min_level': 1},
    'FOCUS_RANGE_HAVOC':   {'min_level': 3},
    'PRESERVE_REGION':     {'min_level': 1},  # can work with token_presence
    'DUPLICATE_REGION':    {'min_level': 3},
    'MOVE_REGION_EARLIER': {'min_level': 3},
    'EXTEND_AFTER_REGION': {'min_level': 3},
    'PRESERVE_AWARE_HAVOC': {'min_level': 1},
    'REJECT_UNSUPPORTED':  {'min_level': 0},
}


def compute_grounding_level(atom, compiled_op):
    """Compute grounding level (0-4) for an atom+op combination.

    Level 0: no evidence → reject
    Level 1: token_presence → evidence_tokens non-empty
    Level 2: token_local_boundary → tokens + boundary evidence or delimiters
    Level 3: focus_range → focus_range available
    Level 4: focus_range_plus_boundary → range + explicit boundary markers
    """
    grounding_reqs = atom.get('grounding_requirements', [])
    evidence_tokens = atom.get('evidence_tokens', [])
    has_tokens = bool(evidence_tokens)
    has_boundary = any(g in grounding_reqs for g in ('boundary_evidence',))
    has_focus = any(g in grounding_reqs for g in ('focus_range',))
    has_focus_opt = 'focus_range_optional' in grounding_reqs

    # Level 4: focus_range + boundary
    if has_focus and has_boundary:
        return 4, 'focus_range_plus_boundary'
    # Level 3: focus_range
    if has_focus or has_focus_opt:
        return 3, 'focus_range'
    # Level 2: tokens + boundary or delimiter
    if has_tokens and has_boundary:
        return 2, 'token_local_boundary'
    # Level 2: tokens from region_roles that imply boundaries
    if has_tokens and atom.get('region_role', '') in (
            'declaration_region', 'constraint_region', 'container_region',
            'delimiter_region', 'termination_region'):
        return 2, 'token_local_boundary'
    # Level 1: token_presence only
    if has_tokens:
        return 1, 'token_presence'
    # Level 0
    return 0, 'none'


def build_grounding_evidence(atom, level):
    """Build grounding evidence dict."""
    return {
        'evidence_tokens': atom.get('evidence_tokens', []),
        'focus_range': atom.get('focus_range'),
        'boundary_evidence': atom.get('boundary_evidence'),
    }


def load_capabilities(path):
    if path and os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {'operators': {}}


def lower_atom_to_actions(atom, capabilities, action_id_counter):
    """Lower a single ontology atom to compiled mutator actions with classification and grounding."""
    effect = atom.get('desired_effect', '')
    if effect not in LOWERING_TABLE:
        return [], [{'atom_id': atom.get('atom_id', 'unknown'),
                      'reason': f'unknown desired_effect: {effect}', 'op': 'unknown'}]

    ops = LOWERING_TABLE[effect]
    evidence_tokens = atom.get('evidence_tokens', [])
    role = atom.get('region_role', '')
    confidence = atom.get('confidence', 0.5)
    atom_id = atom.get('atom_id', 'unknown')

    if 'REJECT_UNSUPPORTED' in ops:
        return [], [{'atom_id': atom_id,
                      'reason': f'unsupported_or_rejected: {atom.get("rationale", "")}',
                      'op': 'REJECT_UNSUPPORTED'}]

    actions = []
    rejected = []
    action_id = action_id_counter

    for op in ops:
        action_id += 1
        level, level_kind = compute_grounding_level(atom, op)
        op_req = OPERATOR_GROUNDING.get(op, {'min_level': 1})
        min_level = op_req['min_level']

        base_act = {
            'action_id': f'ACT_{atom_id}_{action_id:03d}',
            'source_atom': atom_id,
            'op': op,
            'action_class': classify_action(op),
            'can_change_input': op in ACTIVE_MUTATION_OPS,
            'can_drive_transition': op in ACTIVE_MUTATION_OPS,
            'region_role': role,
            'desired_effect': effect,
            'evidence_tokens': [],
            'scope': 'focus_range_or_token_scan',
            'confidence': confidence,
            'source': 'ontology_compiler',
            'grounding_level': level,
            'grounding_kind': level_kind,
            'grounding_evidence': build_grounding_evidence(atom, level),
        }

        # Check if grounding level is sufficient
        if level < min_level:
            # Try fallback
            fallback_op = op_req.get('fallback_to')
            fallback_min = op_req.get('fallback_min_level', 1)
            if fallback_op and level >= fallback_min:
                # Compile as fallback op instead
                action_id += 1
                fallback_act = dict(base_act)
                fallback_act['action_id'] = f'ACT_{atom_id}_{action_id:03d}'
                fallback_act['op'] = fallback_op
                fallback_act['action_class'] = classify_action(fallback_op)
                fallback_act['can_change_input'] = fallback_op in ACTIVE_MUTATION_OPS
                fallback_act['can_drive_transition'] = fallback_op in ACTIVE_MUTATION_OPS
                fallback_act['grounding_level'] = level
                fallback_act['grounding_kind'] = level_kind
                fallback_act['fallback_from'] = op
                fallback_act['fallback_reason'] = (
                    f'{op} requires grounding_level>={min_level} (got {level}); '
                    f'compiled {fallback_op} instead')

                # Apply evidence tokens for token-dependent ops
                if fallback_op == 'REMOVE_TOKENS':
                    fallback_act['evidence_tokens'] = evidence_tokens
                    fallback_act['scope'] = 'token_scan'

                # Capability check
                caps = capabilities.get('operators', {}).get(fallback_op, {})
                if not caps.get('supported', True):
                    rejected.append({'atom_id': atom_id, 'action_id': fallback_act['action_id'],
                                     'reason': caps.get('reason_unsupported', f'{fallback_op} not supported'),
                                     'op': fallback_op})
                    continue

                actions.append(fallback_act)
                continue
            else:
                rejected.append({'atom_id': atom_id, 'action_id': base_act['action_id'],
                                 'reason': f'{op} requires grounding_level>={min_level} (got {level}, kind={level_kind})',
                                 'op': op, 'grounding_level': level,
                                 'grounding_kind': level_kind})
                continue

        # Apply evidence tokens
        if op in ('REMOVE_TOKENS', 'FORBID_TOKENS', 'INSERT_TOKEN_IN_REGION') and evidence_tokens:
            base_act['evidence_tokens'] = evidence_tokens
        if op == 'PRESERVE_REGION' and level < 2:
            base_act['scope'] = 'whole_seed_fallback'

        # Capability check
        caps = capabilities.get('operators', {}).get(op, {})
        if not caps.get('supported', True):
            rejected.append({'atom_id': atom_id, 'action_id': base_act['action_id'],
                             'reason': caps.get('reason_unsupported', f'{op} not supported'),
                             'op': op})
            continue

        actions.append(base_act)

    return actions, rejected


def compile_ontology_atoms(atoms_data, capabilities):
    """Compile ontology atom set to action plan."""
    transition_id = atoms_data.get('transition_id', 'unknown')
    desired_outcome = atoms_data.get('desired_outcome')
    semantic_atoms = atoms_data.get('semantic_atoms', [])

    all_actions, all_rejected = [], []
    aid_counter = 0

    for atom in semantic_atoms:
        actions, rejected = lower_atom_to_actions(atom, capabilities, aid_counter)
        all_actions.extend(actions)
        all_rejected.extend(rejected)
        aid_counter += len(actions) + len(rejected) + 1

    # Classify
    active_mutation = [a for a in all_actions if a['action_class'] == 'active_mutation']
    passive = [a for a in all_actions if a['action_class'] == 'passive_constraint']
    rejected_ops = [a for a in all_actions if a['action_class'] == 'reject']

    forbidden_tokens = []
    for act in all_actions:
        if act['op'] == 'FORBID_TOKENS':
            forbidden_tokens.extend(act.get('evidence_tokens', []))

    executable = len(active_mutation) > 0

    action_plan = {
        'schema_version': 'ftfuzz.ontology_action_plan.v1',
        'ontology_schema_version': atoms_data.get('schema_version', ''),
        'transition_id': transition_id,
        'desired_outcome': desired_outcome,
        'executable': executable,
        'source_atoms': [a.get('atom_id', '') for a in semantic_atoms],
        'compiled_actions': all_actions,
        'forbidden_tokens': sorted(set(forbidden_tokens)),
        'rejected_atoms': all_rejected,
        'compilation_stats': {
            'source_atoms': len(semantic_atoms),
            'compiled_actions': len(all_actions),
            'active_mutation_actions': len(active_mutation),
            'passive_constraints': len(passive),
            'rejected': len(all_rejected),
            'forbidden_token_count': len(set(forbidden_tokens)),
        },
        # Summary for closure validation
        'active_mutation_actions': [a['action_id'] for a in active_mutation],
        'passive_constraints': [a['action_id'] for a in passive],
    }

    report = {
        'schema_version': 'ftfuzz.ontology_action_compilation_report.v1',
        'transition_id': transition_id,
        'desired_outcome': desired_outcome,
        'executable': executable,
        'source_atoms': len(semantic_atoms),
        'actions_compiled': len(all_actions),
        'active_mutation_compiled': len(active_mutation),
        'passive_constraints_compiled': len(passive),
        'actions_rejected': len(all_rejected),
        'rejection_reasons': defaultdict(int),
        'lowering_decisions': [],
    }

    for atom in semantic_atoms:
        effect = atom.get('desired_effect', '')
        ops = LOWERING_TABLE.get(effect, ['UNKNOWN'])
        level, kind = compute_grounding_level(atom, ops[0] if ops else 'UNKNOWN')
        report['lowering_decisions'].append({
            'atom_id': atom.get('atom_id', ''),
            'desired_effect': effect,
            'region_role': atom.get('region_role', ''),
            'lowered_to': ops,
            'grounding_level': level,
            'grounding_kind': kind,
            'confidence': atom.get('confidence', 0),
        })

    for r in all_rejected:
        reason = r.get('reason', 'unknown')
        report['rejection_reasons'][reason] += 1
    report['rejection_reasons'] = dict(report['rejection_reasons'])

    return action_plan, report


def main():
    p = argparse.ArgumentParser(description='Ontology-to-Action Policy Compiler')
    p.add_argument('--atoms', required=True)
    p.add_argument('--capabilities', default=None)
    p.add_argument('--out', default='ontology_action_plan.json')
    p.add_argument('--report', default='compilation_report.json')
    args = p.parse_args()

    capabilities = load_capabilities(args.capabilities)

    with open(args.atoms, 'r') as f:
        atoms_data = json.load(f)

    tid = atoms_data.get('transition_id', 'unknown')
    desired = atoms_data.get('desired_outcome')

    if desired is None:
        print(f"[ERROR] Cannot compile: desired_outcome is missing", file=sys.stderr)
        sys.exit(1)

    print(f"[DIRECTION] transition={tid} desired={desired}")

    action_plan, report = compile_ontology_atoms(atoms_data, capabilities)

    active_n = report['active_mutation_compiled']
    passive_n = report['passive_constraints_compiled']
    executable = "EXECUTABLE" if report['executable'] else "PASSIVE_ONLY"
    print(f"[ONTO_COMPILE] transition={tid} atoms={report['source_atoms']} "
          f"active={active_n} passive={passive_n} rejected={report['actions_rejected']} "
          f"status={executable}")

    for a in action_plan.get('compiled_actions', []):
        print(f"  {a['action_id']}: op={a['op']} class={a['action_class']} "
              f"level={a.get('grounding_level', 0)}/{a.get('grounding_kind', '?')}")
    for r in action_plan.get('rejected_atoms', []):
        print(f"  REJECTED: {r.get('atom_id', '?')}: {r.get('reason', '?')[:100]}")

    for path in [args.out, args.report]:
        d = os.path.dirname(path)
        if d: os.makedirs(d, exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump(action_plan, f, indent=2)
    with open(args.report, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[OUTPUT] {args.out}")


if __name__ == '__main__':
    main()
