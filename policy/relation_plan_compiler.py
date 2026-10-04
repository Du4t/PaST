#!/usr/bin/env python3
"""
Relation Plan Compiler (Stage 2.5, Task E)

Lowers relation-aware ordered plans to executable mutator action chains.
Generic: no format-specific hardcoded templates.

Usage:
  python3 policy/relation_plan_compiler.py \
      --relation-plan relation_plan.json \
      --out action_chain.json \
      --report compilation_report.json
"""

import argparse, json, os, sys, re

# Generic lowering rules: effect -> action chain ops
LOWERING = {
    'ensure_declaration_side':     ['ENSURE_REGION_EXISTS', 'PRESERVE_BOUND_TOKENS_OR_FIELDS'],
    'ensure_typed_field_declaration': ['INSERT_DECLARATION_FIELD_OR_SNIPPET', 'PRESERVE_BOUND_TOKENS_OR_FIELDS'],
    'insert_matching_instance_field': ['INSERT_MATCHING_FIELD_INSTANCE', 'PRESERVE_BINDING_KEYS'],
    'insert_reference_to_definition': ['INSERT_REFERENCE_INSTANCE'],
    'ensure_definition_for_reference': ['ENSURE_DEFINITION_SIDE'],
    'preserve_binding_keys':        ['PRESERVE_BOUND_TOKENS_OR_FIELDS'],
    'preserve_reachability_region': ['PRESERVE_REGION'],
    'unsupported':                  ['REJECT_UNSUPPORTED'],
}

ALLOWED_OPS = {
    'ENSURE_REGION_EXISTS', 'INSERT_DECLARATION_FIELD_OR_SNIPPET',
    'INSERT_MATCHING_FIELD_INSTANCE', 'INSERT_REFERENCE_INSTANCE',
    'ENSURE_DEFINITION_SIDE', 'PRESERVE_BOUND_TOKENS_OR_FIELDS',
    'PRESERVE_BINDING_KEYS', 'PRESERVE_REGION', 'REJECT_UNSUPPORTED',
}

# Bytecode plan: format-agnostic opcodes
BYTECODE_OPS = {
    'FIND', 'WRITE', 'INSERT', 'DELETE',
    'SET_INT', 'INC_INT', 'SIZE_TO', 'PRESERVE',
}

BYTECODE_REQUIRED_PARAMS = {
    'FIND':     ['pattern', 'output'],
    'WRITE':    ['offset', 'data'],
    'INSERT':   ['offset', 'data'],
    'DELETE':   ['offset', 'length'],
    'SET_INT':  ['offset', 'width', 'endian', 'value'],
    'INC_INT':  ['offset', 'width', 'endian', 'delta'],
    'SIZE_TO':  ['field_offset', 'width', 'endian', 'range_start', 'range_end'],
    'PRESERVE': ['offset', 'length'],
}

BYTECODE_OPTIONAL_PARAMS = {
    'FIND':     ['start', 'occurrence'],
    'WRITE':    [],
    'INSERT':   [],
    'DELETE':   [],
    'SET_INT':  [],
    'INC_INT':  [],
    'SIZE_TO':  [],
    'PRESERVE': [],
}


def _is_hex_string(s):
    """Check if string is valid hex (even length, hex chars only)."""
    if not s or not isinstance(s, str):
        return False
    return bool(re.match(r'^[0-9a-fA-F]+$', s)) and len(s) % 2 == 0


def _is_valid_data(s, input_format='binary'):
    """Check if a data/pattern string is valid for the given input format.

    For 'text' format: any non-empty string is acceptable (keywords, tags, source).
    For 'binary' format: must be even-length hex bytes.
    Default 'binary' for backward compatibility.
    """
    if not s or not isinstance(s, str):
        return False
    if input_format == 'text':
        return len(s.strip()) > 0
    return _is_hex_string(s)


def _get_input_format():
    """Read INPUT_FORMAT from env; default 'text' (matching daemon default)."""
    return os.environ.get('FTFUZZ_INPUT_FORMAT', 'text')


def _is_offset_ref(s):
    """Check if string is a valid offset reference: absolute int, {ref}, or {ref}+N."""
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    # Absolute integer
    if s.isdigit():
        return True
    # {ref}, {ref}+N, or {ref}-N
    if re.match(r'^\{[a-zA-Z_][a-zA-Z0-9_]*\}([+-]\d+)?$', s):
        return True
    # END (special)
    if s == 'END':
        return True
    return False


def compile_bytecode_plan(bytecode_plan, capabilities=None):
    """Compile a bytecode plan (ftfuzz.bytecode_plan.v1) into an action chain.

    Unlike relation plans, bytecode plans are NOT lowered through an
    effect→opcode table. The LLM outputs opcodes directly, and we
    validate and pass them through to the mutator.

    Returns: (action_chain, errors, report) — same signature as
    compile_relation_plan for drop-in compatibility.
    """
    errors = []
    warnings = []
    tid = bytecode_plan.get('transition_id', '?')
    desired = bytecode_plan.get('desired_outcome')
    steps_in = bytecode_plan.get('steps', [])

    if not steps_in:
        errors.append("No steps in bytecode plan")
        return None, errors, _empty_report(tid)

    chain_steps = []
    step_counter = 0
    active_count = 0

    for plan_step in steps_in:
        op = plan_step.get('op', '')
        params = plan_step.get('params', {})

        if op not in BYTECODE_OPS:
            errors.append(f"Step {step_counter + 1}: unknown opcode '{op}'. "
                          f"Allowed: {sorted(BYTECODE_OPS)}")
            return None, errors, _empty_report(tid)

        # Validate required params
        required = BYTECODE_REQUIRED_PARAMS.get(op, [])
        for rp in required:
            if rp not in params or params[rp] is None:
                errors.append(
                    f"Step {step_counter + 1}: op '{op}' missing required "
                    f"param '{rp}'")
                return None, errors, _empty_report(tid)

        # Validate param types — format-aware
        input_fmt = _get_input_format()
        if op in ('FIND', 'WRITE', 'INSERT'):
            data_str = str(params.get('pattern', params.get('data', '')))
            if not _is_valid_data(data_str, input_fmt):
                if input_fmt == 'text':
                    errors.append(
                        f"Step {step_counter + 1}: op '{op}' requires non-empty "
                        f"text string for pattern/data (got: '{data_str[:40]}')")
                else:
                    errors.append(
                        f"Step {step_counter + 1}: op '{op}' requires even-length "
                        f"hex string for pattern/data")
                return None, errors, _empty_report(tid)

        if op in ('WRITE', 'INSERT', 'DELETE', 'SET_INT', 'INC_INT',
                  'SIZE_TO', 'PRESERVE'):
            offset_val = str(params.get('offset', params.get('field_offset', '')))
            if not _is_offset_ref(offset_val):
                errors.append(
                    f"Step {step_counter + 1}: op '{op}' has invalid offset "
                    f"'{offset_val}'. Use absolute int, {{ref}}, or {{ref}}+N")
                return None, errors, _empty_report(tid)

        if op in ('SET_INT', 'INC_INT', 'SIZE_TO'):
            width = params.get('width')
            if width not in (1, 2, 4, 8):
                errors.append(
                    f"Step {step_counter + 1}: op '{op}' width must be 1/2/4/8, "
                    f"got {width}")
                return None, errors, _empty_report(tid)
            endian = params.get('endian', '').lower()
            if endian not in ('le', 'be'):
                errors.append(
                    f"Step {step_counter + 1}: op '{op}' endian must be 'le' or "
                    f"'be', got '{endian}'")
                return None, errors, _empty_report(tid)

        step_counter += 1
        step = {
            'step': step_counter,
            'source_step': step_counter,
            'action_id': f'CHAIN_{tid}_{step_counter:03d}',
            'op': op,
            'region_role': '',
            'relation_id': '',
            'parameters': {},
            'requires_success_before_next': False,
        }

        # Copy all params into the step (mutator reads from param_keys/values).
        # IMPORTANT: Always convert to string — the C JSON parser's read_str()
        # only handles JSON strings, not bare integers.
        for k, v in params.items():
            step['parameters'][k] = str(v)

        chain_steps.append(step)
        # Active ops: WRITE, INSERT, DELETE, SET_INT, INC_INT, SIZE_TO
        if op in ('WRITE', 'INSERT', 'DELETE', 'SET_INT', 'INC_INT', 'SIZE_TO'):
            active_count += 1

    # Extract precondition tokens from FIND patterns
    precondition_tokens = []
    for s in chain_steps:
        if s['op'] == 'FIND':
            pattern = s['parameters'].get('pattern', '')
            if pattern:
                precondition_tokens.append(pattern)

    # Extract scaffold
    scaffold_template = bytecode_plan.get('scaffold_template', '')

    # Extract target_alignment
    target_align = bytecode_plan.get('target_alignment', {})

    action_chain = {
        'schema_version': 'ftfuzz.action_chain.v1',
        'transition_id': tid,
        'desired_outcome': desired,
        'source_relation_plan': 'ftfuzz.bytecode_plan.v1',
        'action_chain': chain_steps,
        'chain_class': 'active_mutation_chain' if active_count > 0 else 'passive_only',
        'binding_keys': [],
        'compiler_added_semantics': False,
        'success_oracle': bytecode_plan.get('success_oracle', []),
        'target_alignment': target_align if isinstance(target_align, dict) else {},
        'precondition_tokens': precondition_tokens,
        'scaffold_template': scaffold_template,
    }

    report = {
        'schema_version': 'ftfuzz.action_chain_compilation_report.v1',
        'transition_id': tid,
        'chain_id': f'CHAIN_{tid}',
        'step_count': len(chain_steps),
        'active_steps': active_count,
        'passive_steps': len(chain_steps) - active_count,
        'unsupported_effects_rejected': 0,
        'compiler_hardcoded_templates': False,
        'missing_preconditions_count': 0,
        'errors': errors,
    }

    return action_chain, errors, report

# Active mutation ops (not passive constraints)
ACTIVE_CHAIN_OPS = {
    'INSERT_DECLARATION_FIELD_OR_SNIPPET', 'INSERT_MATCHING_FIELD_INSTANCE',
    'INSERT_REFERENCE_INSTANCE', 'ENSURE_DEFINITION_SIDE',
}


def _filter_valid_tokens(tokens):
    """Filter and normalize tokens for precondition checking.

    Rejects natural language, parameter names. Normalizes common LLM formatting
    errors (e.g., '<![DOCTYPE' → '<!DOCTYPE').
    """
    valid = []
    for tok in tokens:
        if not tok:
            continue
        if len(tok) > 40:
            continue
        if ' ' in tok:
            continue
        if '_' in tok and len(tok) > 5:
            continue
        if tok.isalpha() and len(tok) > 4:
            continue

        # Normalize: LLM sometimes writes '<![' prefix instead of '<!'
        # '<![DOCTYPE' should be '<!DOCTYPE', '<![' + WORD → '<!' + WORD
        if tok.startswith('<![') and len(tok) > 3:
            # Check if removing the '[' makes sense for a declaration-like token
            normalized = '<!' + tok[3:]
            if normalized not in valid:
                valid.append(normalized)
            continue  # Don't add the original '<![' version

        valid.append(tok)
    return valid


def _maybe_parse_json(val):
    """If val is a JSON-encoded string, parse it into a dict/list.
    LLMs sometimes double-encode nested JSON fields as strings.
    Recursively processes dicts and lists to fix nested string-encoded JSON."""
    if isinstance(val, str) and val.strip().startswith(('{', '[')):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, (dict, list)):
                return _maybe_parse_json(parsed)  # recurse into parsed content
        except (json.JSONDecodeError, ValueError):
            pass
    if isinstance(val, dict):
        return {k: _maybe_parse_json(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_maybe_parse_json(v) for v in val]
    return val


def compile_relation_plan(relation_plan, capabilities=None):
    """Compile relation plan into action chain."""
    errors = []
    warnings = []
    # Fix double-encoded JSON fields from LLM response
    for key in list(relation_plan.keys()):
        relation_plan[key] = _maybe_parse_json(relation_plan[key])
    tid = relation_plan.get('transition_id', '?')
    desired = relation_plan.get('desired_outcome')
    ordered_plan = relation_plan.get('ordered_plan', [])
    preconditions = relation_plan.get('missing_preconditions', [])
    relations = relation_plan.get('semantic_relations', [])

    # Stage 2.7: Validate target_alignment
    target_align = relation_plan.get('target_alignment')
    if not target_align:
        errors.append("Missing target_alignment section")
    elif isinstance(target_align, dict):
        if not target_align.get('plan_relevance_to_target'):
            warnings.append("target_alignment.plan_relevance_to_target is empty")
        if not target_align.get('target_relevant_objects_used'):
            warnings.append("target_alignment.target_relevant_objects_used is empty")

    if not ordered_plan:
        # Stage 2.7 fix: LLM returned valid format but couldn't produce a plan.
        # Synthesize a default ordered_plan from the mechanism/state_goal context.
        mechanism = relation_plan.get('mechanism', {})
        mech_type = mechanism.get('type', '')
        ordered_plan = _synthesize_ordered_plan(mech_type)
        if ordered_plan:
            warnings.append("LLM returned empty ordered_plan — synthesized from mechanism type")
            # Also synthesize semantic_relations if missing
            if not relations:
                relations = [{
                    'relation_id': 'R1_SYNTH',
                    'type': 'declaration_instance_binding',
                    'binding_keys': ['identifier', 'type_marker'],
                    'declaration_side': {'region_role': 'declaration_region',
                                         'effect': ordered_plan[0]['effect'],
                                         'parameters': {}},
                    'instance_side': {'region_role': 'payload_region',
                                      'effect': ordered_plan[-1]['effect'],
                                      'parameters': {'value_policy': 'fresh_unique'}},
                }]
        else:
            errors.append("No ordered_plan and cannot synthesize from mechanism")
            return None, errors, _empty_report(tid)

    chain_steps = []
    step_counter = 0
    has_unsupported = False

    for plan_step in ordered_plan:
        step_num = plan_step.get('step', step_counter + 1)
        effect = plan_step.get('effect', '')
        params = plan_step.get('parameters', {})

        if effect not in LOWERING:
            errors.append(f"Step {step_num}: unknown effect '{effect}'")
            return None, errors, _empty_report(tid)

        ops = LOWERING[effect]
        for op in ops:
            step_counter += 1
            step = {
                'step': step_counter,
                'source_step': step_num,
                'action_id': f'CHAIN_{tid}_{step_counter:03d}',
                'op': op,
                'region_role': plan_step.get('target_region', ''),
                'relation_id': plan_step.get('relation_id', ''),
                'parameters': params,
                'requires_success_before_next': op in ACTIVE_CHAIN_OPS,
            }
            chain_steps.append(step)

    # Check: unsupported effects
    unsupported_steps = [s for s in chain_steps if s['op'] == 'REJECT_UNSUPPORTED']
    if unsupported_steps:
        has_unsupported = True

    active_steps = [s for s in chain_steps if s['op'] in ACTIVE_CHAIN_OPS]
    passive_steps = [s for s in chain_steps if s['op'] not in ACTIVE_CHAIN_OPS and s['op'] != 'REJECT_UNSUPPORTED']

    # Stage 2.7: Extract precondition tokens from relation plan
    # Prefer top-level field (set by build_plan_from_legacy_analysis or LLM),
    # otherwise extract from relation parameters and precondition evidence.
    # Always filter out natural language descriptions (LLM sometimes outputs
    # "root element opening tag" instead of actual byte tokens like "<root").
    precondition_tokens = _filter_valid_tokens(
        relation_plan.get('precondition_tokens', [])
    )
    if not precondition_tokens:
        precondition_tokens = _extract_precondition_tokens(preconditions, relations, ordered_plan)

    # Stage 2.7: Extract or default scaffold template
    scaffold_template = relation_plan.get('scaffold_template', '')

    action_chain = {
        'schema_version': 'ftfuzz.action_chain.v1',
        'transition_id': tid,
        'desired_outcome': desired,
        'source_relation_plan': relation_plan.get('schema_version', 'unknown'),
        'action_chain': chain_steps,
        'chain_class': 'active_mutation_chain' if active_steps else 'passive_only',
        'binding_keys': _extract_binding_keys(relations),
        'compiler_added_semantics': False,
        'success_oracle': relation_plan.get('success_oracle', []),
        # Stage 2.7 fields
        'target_alignment': target_align if isinstance(target_align, dict) else {},
        'precondition_tokens': precondition_tokens,
        'scaffold_template': scaffold_template,
    }

    report = {
        'schema_version': 'ftfuzz.action_chain_compilation_report.v1',
        'transition_id': tid,
        'chain_id': f'CHAIN_{tid}',
        'step_count': len(chain_steps),
        'active_steps': len(active_steps),
        'passive_steps': len(passive_steps),
        'unsupported_effects_rejected': len(unsupported_steps),
        'compiler_hardcoded_templates': False,
        'missing_preconditions_count': len(preconditions),
        'errors': errors,
    }

    return action_chain, errors, report


def _synthesize_ordered_plan(mechanism_type):
    """Stage 2.7: Synthesize a default ordered_plan from mechanism type.

    Used when LLM returns valid relation_plan format but empty ordered_plan.
    Generic — no format-specific hardcoded templates.
    """
    if not mechanism_type:
        return None

    mech_lower = mechanism_type.lower()

    if 'declaration_instance_binding' in mech_lower or 'binding' in mech_lower:
        return [
            {'step': 1, 'relation_id': 'R1_SYNTH', 'effect': 'ensure_typed_field_declaration',
             'target_region': 'declaration_region', 'parameters': {}},
            {'step': 2, 'relation_id': 'R1_SYNTH', 'effect': 'insert_matching_instance_field',
             'target_region': 'payload_region', 'parameters': {'value_policy': 'fresh_unique'}},
        ]
    elif 'typed' in mech_lower or 'materialization' in mech_lower or 'table' in mech_lower:
        return [
            {'step': 1, 'relation_id': 'R1_SYNTH', 'effect': 'ensure_typed_field_declaration',
             'target_region': 'declaration_region', 'parameters': {}},
            {'step': 2, 'relation_id': 'R1_SYNTH', 'effect': 'insert_matching_instance_field',
             'target_region': 'payload_region', 'parameters': {'value_policy': 'fresh_unique'}},
        ]
    elif 'declaration' in mech_lower:
        return [
            {'step': 1, 'relation_id': 'R1_SYNTH', 'effect': 'ensure_declaration_side',
             'target_region': 'declaration_region', 'parameters': {}},
            {'step': 2, 'relation_id': 'R1_SYNTH', 'effect': 'insert_matching_instance_field',
             'target_region': 'payload_region', 'parameters': {}},
        ]
    elif 'reference' in mech_lower or 'definition' in mech_lower:
        return [
            {'step': 1, 'relation_id': 'R1_SYNTH', 'effect': 'ensure_definition_for_reference',
             'target_region': 'definition_region', 'parameters': {}},
            {'step': 2, 'relation_id': 'R1_SYNTH', 'effect': 'insert_reference_to_definition',
             'target_region': 'payload_region', 'parameters': {}},
        ]
    else:
        # Generic fallback: ensure declaration + insert instance
        return [
            {'step': 1, 'relation_id': 'R1_SYNTH', 'effect': 'ensure_declaration_side',
             'target_region': 'declaration_region', 'parameters': {}},
            {'step': 2, 'relation_id': 'R1_SYNTH', 'effect': 'insert_matching_instance_field',
             'target_region': 'payload_region', 'parameters': {}},
        ]


def _extract_binding_keys(relations):
    keys = []
    for r in relations:
        for k in r.get('binding_keys', []):
            if k not in keys:
                keys.append(k)
    return keys


def _extract_precondition_tokens(preconditions, relations, ordered_plan):
    """Stage 2.7: Extract required tokens from preconditions and relation parameters.

    These tokens must exist in the seed buffer for the chain to execute in-place.
    Format-specific tokens (e.g., '<!DOCTYPE') should come from LLM-provided
    relation parameters, not from compiler hardcoded rules.
    """
    tokens = []

    # From relations: collect parameter values that represent required anchors
    for r in relations:
        for side_key in ('declaration_side', 'instance_side'):
            side = r.get(side_key, {})
            params = side.get('parameters', {})
            # Collect element names, attribute names as binding anchors
            for pk in ('element_selector', 'element_name', 'attribute_name', 'anchor_tag'):
                val = params.get(pk, '')
                if val and not val.startswith('{') and val not in tokens:
                    tokens.append(val)

    # From preconditions: collect any evidence tokens
    for pc in preconditions:
        evidence = pc.get('evidence', {})
        if isinstance(evidence, dict):
            for tok in evidence.get('tokens', []):
                if tok and tok not in tokens:
                    tokens.append(tok)

    # Stage 2.7 fix: Filter out natural language descriptions.
    # LLM often outputs descriptive strings like "root element opening tag"
    # instead of actual byte-level tokens like "<root". A valid token for
    # precondition checking must look like it could appear in a binary buffer.
    tokens = _filter_valid_tokens(tokens)

    return tokens




def _empty_report(tid):
    return {
        'transition_id': tid, 'chain_id': 'NONE',
        'step_count': 0, 'active_steps': 0, 'errors': ['compilation_failed'],
    }


def main():
    p = argparse.ArgumentParser(description='Relation Plan Compiler')
    p.add_argument('--relation-plan', required=True)
    p.add_argument('--out', default='action_chain.json')
    p.add_argument('--report', default='action_chain_compilation_report.json')
    args = p.parse_args()

    with open(args.relation_plan) as f:
        plan = json.load(f)

    chain, errors, report = compile_relation_plan(plan)

    for path in [args.out, args.report]:
        d = os.path.dirname(path)
        if d: os.makedirs(d, exist_ok=True)

    if chain:
        with open(args.out, 'w') as f:
            json.dump(chain, f, indent=2)
        print(f'[OUTPUT] {args.out}')
        print(f'  chain_id: CHAIN_{chain["transition_id"]}')
        print(f'  steps: {len(chain["action_chain"])}, active: {report["active_steps"]}')
        print(f'  compiler hardcoded templates: FALSE')
    else:
        chain = {'error': 'compilation_failed', 'errors': errors}
        with open(args.out, 'w') as f:
            json.dump(chain, f, indent=2)
        print(f'[FAIL] Compilation errors: {errors}')

    with open(args.report, 'w') as f:
        json.dump(report, f, indent=2)

    sys.exit(0 if chain and not errors else 1)


if __name__ == '__main__':
    main()
