#!/usr/bin/env python3
"""
FTFuzz Internal Symbol Filter — prevents C/C++ internal program symbols
from being used as dictionary tokens in policy groups.

Filters tokens matching: struct fields, enum constants, function names,
macros, type names, pointer expressions, and internal identifiers.

Usage:
  python3 policy/internal_symbol_filter.py \\
      --policy-store policy_store_v2.json \\
      --output policy_store_v2.filtered.json \\
      --report internal_symbol_filter_report.json
"""

import argparse, json, os, re, sys


INTERNAL_PATTERNS = [
    re.compile(r'->'),                     # pointer deref
    re.compile(r'::'),                     # C++ scope
    re.compile(r'^\*|&\w+$'),              # pointer/ref
    re.compile(r'^[A-Z_]{3,}$'),           # ALL_CAPS macros/enums
    re.compile(r'(?i)^xml[A-Z]'),          # libxml2 API prefix
    re.compile(r'(?i)ctxt'),               # parser context
    re.compile(r'(?i)(Ptr|Func|Err|SAX|EOF|MAGIC)'),  # internal type suffixes
    re.compile(r'^[a-z]+[A-Z][a-z]+[A-Z]'), # CamelCase (looks like type/function)
]

INTERNAL_SUBSTRINGS = [
    'ctxt', 'disableSAX', 'instate', 'errNo', 'serror',
    'sax', 'SAX', 'Parser', 'Valid', 'EOF', 'MAGIC',
    'StructuredError', 'ParserCtxt', 'Snprintf',
]


def is_internal_symbol(token):
    """Return (is_internal, reason) for a token."""
    reasons = []
    for pat in INTERNAL_PATTERNS:
        if pat.search(token):
            reasons.append(pat.pattern)
    for sub in INTERNAL_SUBSTRINGS:
        if sub.lower() in token.lower():
            reasons.append(f'contains:{sub}')
    if reasons:
        return True, ';'.join(reasons[:3])
    return False, ''


def is_input_literal(token):
    """Check if token looks like it could be an input format literal."""
    xml_keywords = {'<!DOCTYPE', '<!ELEMENT', '<!ATTLIST', '<!ENTITY', '<!NOTATION',
                    '#PCDATA', 'EMPTY', 'ANY', 'CDATA', 'SYSTEM', 'PUBLIC',
                    'NDATA', '#FIXED', '#IMPLIED', '#REQUIRED',
                    '<?xml', 'encoding=', 'version=', 'standalone=',
                    '<![CDATA[', ']]>', 'xmlns', 'xmlns:'}
    if token in xml_keywords:
        return True
    if token.startswith('<') or token.startswith('#'):
        return True
    return False


def filter_policy_store(ps):
    """Filter internal symbols from all policy groups."""
    report = {}
    for gid, g in ps.get('policy_groups', {}).items():
        tokens = g.get('mutation_actions', {}).get('dictionary_tokens', [])
        kept = []
        filtered = []

        for t in tokens:
            tok = t.get('token', '') if isinstance(t, dict) else str(t)
            if is_input_literal(tok):
                kept.append(t)
                continue
            is_int, reason = is_internal_symbol(tok)
            if is_int:
                filtered.append({'token': tok, 'reason': reason})
            else:
                kept.append(t)

        # Build semantic edit plan from filtered insights
        edit_plan = _compile_edit_plan(g, filtered)

        report[gid] = {
            'raw_tokens': [t.get('token', '') if isinstance(t, dict) else str(t) for t in tokens],
            'kept_tokens': [t.get('token', '') if isinstance(t, dict) else str(t) for t in kept],
            'filtered_internal_symbols': filtered,
            'semantic_edit_plan': edit_plan,
        }

        # Update group in-place
        g['mutation_actions']['dictionary_tokens'] = kept
        g['semantic_edit_plan'] = edit_plan  # top-level, not inside mutation_actions

    return ps, report


def _compile_edit_plan(g, filtered):
    """Compile generic edit plan from filtered symbols and semantic hints."""
    sem = g.get('semantic_basis', {}).get('transition_constraints', {})
    preserve_hints = sem.get('preserve', [])
    focus_hints = sem.get('mutate_focus', [])

    # Inferred barrier kind from semantic hints
    barrier_kind = 'unknown'
    combined = ' '.join(preserve_hints + focus_hints + [f['token'] for f in filtered])

    if any(kw in combined.lower() for kw in ['eof', 'terminal', 'end-of-file', 'end of file']):
        barrier_kind = 'terminal_state_guard'
    elif any(kw in combined.lower() for kw in ['null', 'null-check', 'null check', 'nullptr']):
        barrier_kind = 'null_guard'
    elif any(kw in combined.lower() for kw in ['disable', 'disabled', 'flag', 'conditional']):
        barrier_kind = 'state_flag_guard'

    internal_state_constraints = []
    for f in filtered:
        internal_state_constraints.append({
            'symbol': f['token'],
            'avoid_value': 'unknown',
            'input_level_implication': f'input must avoid dependency on internal state {f["token"]}',
        })

    # Heuristic: compile edit ops from hints and barrier kind
    edit_ops = []

    if barrier_kind == 'terminal_state_guard':
        edit_ops.append({
            'op': 'EXTEND_AFTER_FOCUS_REGION',
            'target': 'tail_region',
            'purpose': 'delay terminal state after focus region',
            'weight': 1.0,
        })
        edit_ops.append({
            'op': 'EXTEND_TAIL_BY_EXISTING_REGION',
            'target': 'tail_region',
            'purpose': 'append existing content to delay EOF',
            'weight': 0.8,
        })

    if preserve_hints:
        edit_ops.append({
            'op': 'PRESERVE_REACHABILITY_PREFIX',
            'target': 'preserve_range',
            'purpose': 'avoid destroying bytes that reach PreState',
            'weight': 0.9,
        })

    if focus_hints:
        edit_ops.append({
            'op': 'FOCUS_RANGE_LOCAL_HAVOC',
            'target': 'focus_range',
            'purpose': 'vary content within suspected semantic event region',
            'weight': 0.7,
        })
        edit_ops.append({
            'op': 'REPLACE_FOCUS_WITH_EXISTING_REGION',
            'target': 'focus_range',
            'purpose': 'replace focus region with bytes from another seed region',
            'weight': 0.6,
        })

    # Always add a few generic ops
    if not any(o['op'] == 'DUPLICATE_REGION' for o in edit_ops):
        edit_ops.append({
            'op': 'DUPLICATE_REGION',
            'target': 'focus_range',
            'purpose': 'duplicate semantic event region to amplify effect',
            'weight': 0.5,
        })

    return {
        'schema_version': 'ftfuzz.semantic_edit_ir.v1',
        'enabled': len(edit_ops) > 0,
        'barrier_kind': barrier_kind,
        'internal_state_constraints': internal_state_constraints,
        'input_level_implications': [c['input_level_implication'] for c in internal_state_constraints],
        'edit_ops': edit_ops,
    }


def load_json(path):
    with open(path) as f:
        text = f.read()
    try: return json.loads(text)
    except json.JSONDecodeError:
        return json.JSONDecoder().raw_decode(text)[0]


def main():
    p = argparse.ArgumentParser(description='Internal Symbol Filter')
    p.add_argument('--policy-store', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--report', default=None)
    args = p.parse_args()

    ps = load_json(args.policy_store)
    ps, report = filter_policy_store(ps)

    with open(args.output, 'w') as f:
        json.dump(ps, f, indent=2)
    print(f'Wrote {args.output}')

    if args.report:
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f'Filter report: {args.report}')

    for gid, r in report.items():
        n_filtered = len(r['filtered_internal_symbols'])
        n_kept = len(r['kept_tokens'])
        ops = len(r['semantic_edit_plan']['edit_ops'])
        bk = r['semantic_edit_plan']['barrier_kind']
        print(f'{gid}: filtered={n_filtered} kept={n_kept} edit_ops={ops} barrier={bk}')
        for f in r['filtered_internal_symbols'][:5]:
            print('  FILTERED: %s (%s)' % (f['token'], f['reason']))
        for op in r['semantic_edit_plan']['edit_ops'][:5]:
            print('  EDIT_OP: %s target=%s' % (op['op'], op['target']))


if __name__ == '__main__':
    main()
