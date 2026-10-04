#!/usr/bin/env python3
"""
Ontology Atom Validator (Stage 2.3-pre, Task F)

Validates LLM-produced ontology atoms against the ontology schema.

Checks:
  1. schema_version correct
  2. desired_outcome exists and matches transition metadata
  3. each region_role is in allowed enum
  4. each desired_effect is in allowed enum
  5. no internal program symbols appear as evidence_tokens
  6. non_input_symbols are separated
  7. confidence in [0, 1]
  8. atom count > 0 unless LLM says unsupported

Usage:
  python3 policy/ontology_atom_validator.py \
      --atoms llm_output.json \
      --transition-metadata transition_context.json \
      --out ontology_atom_validation_report.json
"""

import argparse
import json
import os
import sys

# Load allowed enums from schema
SCHEMA_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(SCHEMA_DIR, 'mutation_ontology_schema.json')

ALLOWED_REGION_ROLES = {
    "reachability_region", "declaration_region", "constraint_region",
    "reference_region", "payload_region", "tail_region", "termination_region",
    "length_field", "count_field", "offset_field", "checksum_field",
    "delimiter_region", "container_region", "unknown_region",
}

ALLOWED_DESIRED_EFFECTS = {
    "preserve", "remove", "empty", "create", "make_non_empty",
    "remove_or_forbid", "create_or_preserve", "create_or_keep_non_empty",
    "mutate", "move_earlier", "extend_after", "repair_consistency", "unsupported",
}

ALLOWED_GROUNDING = {
    "token_presence", "focus_range", "focus_range_optional",
    "preserve_range", "byte_window", "boundary_evidence", "scope_from_transition",
}

# Patterns that suggest program internal symbols (not input literals)
# Only match C-specific patterns — do NOT flag generic lowercase tokens.
INTERNAL_SYMBOL_PATTERNS = [
    "->", "::", "ctxt->", "parser->", "state->", "doc->",
    "node->", "tree->", "reader->", "writer->",
    "malloc", "sizeof", "NULL",
    "_count", "_flag", "_buf", "_ctx", "_ptr",  # C naming conventions
]


def load_schema_enums():
    """Reload enums from schema file for validation."""
    try:
        with open(SCHEMA_PATH, 'r') as f:
            schema = json.load(f)
        roles = schema.get('definitions', {}).get('RegionRole', {}).get('enum', [])
        effects = schema.get('definitions', {}).get('DesiredEffect', {}).get('enum', [])
        if roles:
            ALLOWED_REGION_ROLES.update(roles)
        if effects:
            ALLOWED_DESIRED_EFFECTS.update(effects)
    except (IOError, json.JSONDecodeError):
        pass


def looks_like_internal_symbol(token):
    """Heuristic: does this token look like a program internal symbol?

    Only flags tokens matching known C patterns or containing '->', '::'.
    Does NOT flag short generic lowercase tokens like 'xml', 'id', 'name'.
    """
    token = token.strip()
    if not token:
        return False
    for pattern in INTERNAL_SYMBOL_PATTERNS:
        if pattern in token:
            return True
    # Only flag C-style identifiers with underscores + lowercase
    # that look like variable names (3+ chars with underscores)
    if '_' in token and token.replace('_', '').isalpha() and token.islower():
        if len(token) > 5:  # longer underscore_names are likely C identifiers
            return True
    return False


def validate_atoms(atoms_data, transition_metadata=None):
    """
    Validate ontology atoms.
    Returns (valid: bool, errors: list, warnings: list, report: dict).
    """
    errors = []
    warnings = []
    atoms_detail = []

    # Check 1: schema_version
    version = atoms_data.get('schema_version', '')
    if version != 'ftfuzz.mutation_ontology_atoms.v1':
        errors.append(f"Invalid schema_version: '{version}', "
                      f"expected 'ftfuzz.mutation_ontology_atoms.v1'")

    # Check 2: desired_outcome
    desired_outcome = atoms_data.get('desired_outcome')
    if desired_outcome is None:
        errors.append("Missing required field: desired_outcome")
    elif not isinstance(desired_outcome, bool):
        errors.append(f"desired_outcome must be boolean, got {type(desired_outcome).__name__}")

    # Check 2b: desired_outcome matches transition metadata
    if transition_metadata and desired_outcome is not None:
        meta_outcome = transition_metadata.get('desired_outcome')
        if meta_outcome is not None and desired_outcome != meta_outcome:
            errors.append(f"desired_outcome mismatch: atoms={desired_outcome}, "
                          f"metadata={meta_outcome}")

    # Check 3: required fields
    transition_id = atoms_data.get('transition_id', '')
    if not transition_id:
        errors.append("Missing required field: transition_id")

    semantic_atoms = atoms_data.get('semantic_atoms', [])

    # Check 8: atom count
    if not isinstance(semantic_atoms, list):
        errors.append(f"semantic_atoms must be an array, got {type(semantic_atoms).__name__}")
        return False, errors, warnings, _build_report(atoms_data, errors, warnings, [])

    has_unsupported = any(a.get('desired_effect') == 'unsupported' for a in semantic_atoms)
    if len(semantic_atoms) == 0 and not has_unsupported:
        errors.append("semantic_atoms is empty but no unsupported effect declared")

    # Check each atom
    atom_ids = set()
    for i, atom in enumerate(semantic_atoms):
        atom_errs = []
        atom_warns = []

        aid = atom.get('atom_id', f'atom[{i}]')

        # Check required fields
        if not atom.get('atom_id'):
            atom_errs.append("missing atom_id")

        # Check 3: region_role
        role = atom.get('region_role', '')
        if not role:
            atom_errs.append("missing region_role")
        elif role not in ALLOWED_REGION_ROLES:
            atom_errs.append(f"invalid region_role: '{role}'")
            # Suggest closest match
            close = [r for r in ALLOWED_REGION_ROLES if role[:4] in r or r[:4] in role]
            if close:
                atom_errs[-1] += f" (did you mean: {close[0]}?)"

        # Check 4: desired_effect
        effect = atom.get('desired_effect', '')
        if not effect:
            atom_errs.append("missing desired_effect")
        elif effect not in ALLOWED_DESIRED_EFFECTS:
            atom_errs.append(f"invalid desired_effect: '{effect}'")

        # Check 5: evidence_tokens should not contain internal symbols
        evidence_tokens = atom.get('evidence_tokens', [])
        for token in evidence_tokens:
            if looks_like_internal_symbol(token):
                atom_errs.append(f"evidence_token '{token}' looks like a program "
                                f"internal symbol, not an input literal")

        # Check 6: non_input_symbols separated
        non_input = atoms_data.get('non_input_symbols', [])
        for nis in non_input:
            nis_symbol = nis.get('symbol', '')
            if nis_symbol in evidence_tokens:
                atom_errs.append(f"'{nis_symbol}' appears in both evidence_tokens "
                                f"and non_input_symbols")

        # Check 7: confidence
        conf = atom.get('confidence')
        if conf is not None:
            if not isinstance(conf, (int, float)):
                atom_errs.append(f"confidence must be a number, got {type(conf).__name__}")
            elif conf < 0.0 or conf > 1.0:
                atom_errs.append(f"confidence {conf} not in [0, 1]")

        # Check grounding requirements
        grounding = atom.get('grounding_requirements', [])
        for g in grounding:
            if g not in ALLOWED_GROUNDING:
                atom_warns.append(f"unknown grounding_requirement: '{g}'")

        # Check rationale
        if not atom.get('rationale'):
            atom_warns.append(f"missing rationale for atom {aid}")

        # Duplicate atom_id check
        if aid in atom_ids:
            atom_warns.append(f"duplicate atom_id: {aid}")
        atom_ids.add(aid)

        if atom_errs:
            for e in atom_errs:
                errors.append(f"[{aid}] {e}")
        if atom_warns:
            for w in atom_warns:
                warnings.append(f"[{aid}] {w}")

        atoms_detail.append({
            'atom_id': aid,
            'valid': len(atom_errs) == 0,
            'errors': atom_errs,
            'warnings': atom_warns,
        })

    # Cross-atom checks
    if len(semantic_atoms) > 1:
        # Check for contradictory effects on same region_role
        role_effects = {}
        for atom in semantic_atoms:
            role = atom.get('region_role', '')
            effect = atom.get('desired_effect', '')
            if role and effect:
                if role not in role_effects:
                    role_effects[role] = set()
                role_effects[role].add(effect)
        for role, effects in role_effects.items():
            if 'preserve' in effects and 'remove' in effects:
                warnings.append(f"Contradictory effects on role '{role}': "
                               f"both preserve and remove")

    valid = len(errors) == 0
    report = _build_report(atoms_data, errors, warnings, atoms_detail)
    return valid, errors, warnings, report


def _build_report(atoms_data, errors, warnings, atoms_detail):
    return {
        'schema_version': 'ftfuzz.ontology_atom_validation_report.v1',
        'valid': len(errors) == 0,
        'transition_id': atoms_data.get('transition_id', ''),
        'desired_outcome': atoms_data.get('desired_outcome'),
        'atom_count': len(atoms_data.get('semantic_atoms', [])),
        'error_count': len(errors),
        'warning_count': len(warnings),
        'errors': errors,
        'warnings': warnings,
        'atoms_detail': atoms_detail,
    }


def main():
    p = argparse.ArgumentParser(description='Ontology Atom Validator')
    p.add_argument('--atoms', required=True,
                   help='Path to LLM ontology atoms JSON output')
    p.add_argument('--transition-metadata', default=None,
                   help='Path to transition runtime context JSON')
    p.add_argument('--out', default='ontology_atom_validation_report.json',
                   help='Output path for validation report')
    args = p.parse_args()

    load_schema_enums()

    with open(args.atoms, 'r') as f:
        atoms_data = json.load(f)
    print(f"[INFO] Loaded {len(atoms_data.get('semantic_atoms', []))} atoms "
          f"for {atoms_data.get('transition_id', 'unknown')}")

    transition_metadata = None
    if args.transition_metadata:
        try:
            with open(args.transition_metadata, 'r') as f:
                transition_metadata = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"[WARN] Could not load transition metadata: {e}")

    valid, errors, warnings, report = validate_atoms(atoms_data, transition_metadata)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.out, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[OUTPUT] Validation report: {args.out}")

    print(f"\n{'='*60}")
    print(f"VALIDATION: {'PASS' if valid else 'FAIL'}")
    print(f"{'='*60}")
    print(f"  Errors:   {len(errors)}")
    for e in errors:
        print(f"    [ERROR] {e}")
    print(f"  Warnings: {len(warnings)}")
    for w in warnings[:10]:
        print(f"    [WARN]  {w}")
    if len(warnings) > 10:
        print(f"    ... and {len(warnings) - 10} more")

    exit(0 if valid else 1)


if __name__ == '__main__':
    main()
