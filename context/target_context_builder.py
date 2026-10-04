#!/usr/bin/env python3
"""
Target Context Builder (Stage 2.7, C3)

Extracts global target function context for target-aware LLM planning.
Uses generic source code heuristics — NO format-specific or target-specific
hardcoded strings.

Usage:
  python3 context/target_context_builder.py \
      --target-function get_ipv6_next \
      --target-file-line src/common/get.c:709 \
      --source-root experiments/targets/tcpreplay \
      --out experiments/output/tcpreplay/context/global_target_context.json
"""

import argparse, json, os, re, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools.source_context import extract_source_snippet


def _call_llm_for_target_summary(snippet, func_name, target_file, target_line, llm_config):
    """Call LLM to produce a semantic summary of the target function."""
    if not llm_config or not llm_config.get('enabled', False):
        return None

    from tools.precompute_state_semantics import call_llm

    prompt = f"""You are analyzing a target function for fuzzing. Given the source code snippet below, explain the function's role and how to reach it.

Function: {func_name}
File: {target_file}:{target_line}

Source snippet:
{snippet[:3000]}

Output a JSON object with these fields:
- "function_purpose": What does this function DO? What is its role in the program? (1-2 sentences)
- "call_conditions": Under what CONDITIONS is this function called? What program state or events must happen BEFORE this function can execute? Be specific.
- "input_properties_to_reach": What INPUT PROPERTIES would cause the program to execute this function? What must the input contain or lack?
- "overrepair_risks": What kind of INPUT would BYPASS this function entirely? What mutations would make the program take a DIFFERENT path that never calls this function?

Output ONLY the JSON object, no other text."""

    result, status = call_llm(prompt, llm_config)
    if result:
        print(f'[TARGET_CTX] LLM summary obtained for {func_name}')
        return result
    print(f'[TARGET_CTX] LLM summary failed: {status}')
    return None


def parse_target_location(file_line_str):
    """Parse 'file:line' format into (file, line). Handles multi-colon paths."""
    parts = file_line_str.rsplit(':', 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return file_line_str, 0


def extract_function_signature(snippet):
    """Generic: extract function parameter types and names from the snippet."""
    params = []
    # Match function definitions: return_type func_name(type1 name1, type2 name2, ...)
    for match in re.finditer(r'\b(\w+)\s+(\w+)\s*\(([^)]*)\)', snippet):
        ret_type, func_name, param_str = match.groups()
        for param in param_str.split(','):
            param = param.strip()
            parts = param.split()
            if len(parts) >= 2:
                params.append({'type': parts[-2], 'name': parts[-1].rstrip('*')})
            elif len(parts) == 1:
                params.append({'type': parts[0], 'name': ''})
    return params


def extract_relevant_objects(snippet):
    """Generic: identify relevant types and variables from source code."""
    objects = set()

    if not snippet:
        return []

    # 1. Struct/typedef types (capitalized or underscored compound names)
    for match in re.finditer(r'\bstruct\s+(\w+)\b', snippet):
        objects.add(match.group(1))

    # 2. Pointer member access (ptr->field) — extract both ptr names and fields
    ptr_names = set()
    for match in re.finditer(r'(\w+)->(\w+)', snippet):
        ptr_names.add(match.group(1))
        field = match.group(2)
        if field not in ('next', 'prev', 'children', 'parent', 'doc', 'last', 'name', 'prefix'):
            objects.add(field)

    # 3. Variable declarations: type var_name
    for match in re.finditer(r'\b(\w+)\s+(\w+)\s*[=;\[]', snippet):
        typ, var = match.groups()
        # Only keep non-trivial types (not int, char, void, etc.)
        if typ not in ('int', 'char', 'void', 'long', 'short', 'float', 'double',
                        'unsigned', 'signed', 'size_t', 'const', 'static', 'if',
                        'for', 'while', 'return', 'switch', 'case', 'default'):
            objects.add(var)

    # 4. Type-cast expressions: (Type *)ptr
    for match in re.finditer(r'\(\s*(\w+)\s*\*\s*\)', snippet):
        objects.add(match.group(1))

    return sorted(objects)


def extract_target_trigger(snippet, target_line):
    """Identify the specific condition/branch that triggers the target LINE.

    Scans source snippet, tracking active switch cases and branch contexts,
    so that when target_line is reached, the active condition is recorded.
    Returns a dict with type, condition, value, and description.
    """
    if not snippet or not target_line:
        return None

    active_case = None
    active_condition = None
    lines = snippet.split('\n')

    for line in lines:
        stripped = line.strip()

        # Extract line number prefix (e.g., "1339: " or "1339:\t")
        line_num = 0
        num_match = re.match(r'^(\d+):', stripped)
        if num_match:
            line_num = int(num_match.group(1))

        # Track switch case context
        case_match = re.search(r'case\s+([^:]+):', stripped)
        if case_match:
            active_case = {
                'value': case_match.group(1).strip(),
                'description': stripped.split('//', 1)[-1].strip() if '//' in stripped else '',
            }

        # Track if condition context (entering a new if block)
        if_match = re.search(r'if\s*\(([^)]+)\)', stripped)
        if if_match and '{' in stripped.split('//')[0]:
            active_condition = if_match.group(1).strip()

        # Check if this is the target line
        if line_num > 0 and line_num == target_line:
            if active_case:
                trigger = {
                    'type': 'switch_case',
                    'condition': active_condition or 'unknown',
                    'case_value': active_case['value'],
                    'description': active_case.get('description', ''),
                    'target_line': target_line,
                }
                return trigger
            if active_condition:
                return {
                    'type': 'conditional_branch',
                    'condition': active_condition,
                    'target_line': target_line,
                }

    return None


def extract_target_conditions(snippet):
    """Generic: identify conditions from branch statements near target line."""
    conditions = []

    if not snippet:
        return ["Source context unavailable — needs manual review"]

    # Extract conditional branches
    for line in snippet.split('\n'):
        stripped = line.strip()
        cond_match = re.search(r'if\s*\(([^)]+)\)', stripped)
        if cond_match:
            cond = cond_match.group(1).strip()
            if len(cond) > 2:
                conditions.append(f"Branch: {cond}")

        # switch cases
        case_match = re.search(r'case\s+([^:]+):', stripped)
        if case_match:
            conditions.append(f"Switch case: {case_match.group(1).strip()}")

        # Error checks
        if any(kw in stripped.lower() for kw in ('error', 'fail', 'invalid', 'null')):
            for match in re.finditer(r'if\s*\(([^)]+)\)', stripped):
                conditions.append(f"Error check: {match.group(1).strip()}")

    if not conditions:
        conditions.append("No explicit branches found at target location")

    return conditions[:10]  # limit to avoid bloating prompt


def derive_overrepair_hints(snippet, conditions):
    """Generic: derive clues about what mutations might bypass the target.

    Look for patterns that indicate the target is reached conditionally:
    error paths, validation checks, buffer limits, switch defaults, etc.
    """
    hints = []

    if not snippet:
        return ["Unknown — manual review recommended"]

    snippet_lower = snippet.lower()

    # Generic patterns that suggest conditional reachability
    if any(kw in snippet_lower for kw in ('error', 'fail', 'invalid', 'warn')):
        hints.append("Target appears to be in an error/failure path — input that avoids all errors may bypass it")

    if any(kw in snippet_lower for kw in ('size', 'len', 'maxlen', 'buf', 'buffer', 'limit')):
        hints.append("Target involves buffer or size checks — inputs within limits may avoid the target path")

    if any(kw in snippet_lower for kw in ('switch', 'case', 'default')):
        hints.append("Target is inside a switch statement — only specific case values reach it")

    if any(kw in snippet_lower for kw in ('abort', 'assert', 'exit')):
        hints.append("Target contains abort/assert — execution stops here; earlier validation determines reachability")

    if any(kw in snippet_lower for kw in ('return null', 'return 0', 'return -1')):
        hints.append("Target has null/error return paths — valid inputs may cause early return before reaching target")

    if 'if' in snippet_lower and 'else' in snippet_lower:
        hints.append("Target has conditional branches — only specific input properties trigger the desired path")

    if not hints:
        hints.append("Unknown — manual review recommended")

    return hints


def infer_state_summary(snippet, func_name, conditions):
    """Generic: generate a state summary from the source snippet alone.

    Analyses the code structure to describe what the function does and
    what conditions are needed to reach specific lines. No hardcoded
    format-specific strings.
    """
    if not snippet:
        return (
            f"Target function '{func_name}' — source not available for static analysis. "
            f"Manual review or LLM summary recommended."
        )

    # Count lines, branches, returns
    num_lines = len([l for l in snippet.split('\n') if l.strip()])
    num_returns = len(re.findall(r'\breturn\b', snippet))
    num_ifs = len(re.findall(r'\bif\s*\(', snippet))
    num_switches = len(re.findall(r'\bswitch\s*\(', snippet))

    # Use the caller-provided function name (from BB map), not snippet inference.
    # Snippet regex often misidentifies macro calls (MAGMA_LOG) as function names.
    summary_parts = [
        f"Function '{func_name}' at the target location."
    ]

    if num_lines > 0:
        summary_parts.append(f"Surrounding code has {num_lines} lines")
    if num_returns > 0:
        summary_parts.append(f"{num_returns} return points")
    if num_ifs > 0:
        summary_parts.append(f"{num_ifs} conditional branches")
    if num_switches > 0:
        summary_parts.append(f"{num_switches} switch statements")

    if conditions:
        relevant = [c for c in conditions if c.startswith('Branch:')][:2]
        if relevant:
            summary_parts.append(f"Key conditions: {'; '.join(c.replace('Branch: ', '') for c in relevant)}")

    summary = '. '.join(summary_parts) + '.'
    summary += ' The specific input properties needed to reach this target depend on the program logic leading to this function.'

    return summary


def build_target_context(source_root, func_name, target_file, target_line, llm_config=None):
    """Build complete global target context using GENERIC source analysis only."""
    snippet_result = extract_source_snippet(source_root, target_file, target_line, context_lines=20)
    snippet = snippet_result.get('snippet', '') if snippet_result.get('available') else ''

    objects = extract_relevant_objects(snippet)
    conditions = extract_target_conditions(snippet)
    hints = derive_overrepair_hints(snippet, conditions)
    trigger = extract_target_trigger(snippet, target_line)

    # Try to infer the actual function name from the snippet if the given
    # func_name looks like a file path (e.g., "src/common/get.c")
    if '/' in func_name or func_name.endswith('.c') or func_name.endswith('.h'):
        # func_name is actually a file path — extract real function name from snippet
        for match in re.finditer(r'\b(\w+)\s+(\w+)\s*\(', snippet):
            inferred = match.group(2)
            if len(inferred) > 2:
                func_name = inferred
                break

    state_summary = infer_state_summary(snippet, func_name, conditions)

    # Optional: get LLM semantic summary
    llm_summary = None
    if llm_config and llm_config.get('enabled', False):
        llm_summary = _call_llm_for_target_summary(snippet, func_name, target_file, target_line, llm_config)

    # Merge LLM output into the context
    if llm_summary:
        # Replace the generic state summary with LLM's function purpose
        llm_purpose = llm_summary.get('function_purpose', '')
        if llm_purpose:
            state_summary = llm_purpose + ' ' + state_summary

        # Add LLM's call conditions to the conditions list
        llm_conditions = llm_summary.get('call_conditions', '')
        if llm_conditions:
            conditions.insert(0, f"LLM: {llm_conditions}")

        # Add LLM's input properties
        llm_input = llm_summary.get('input_properties_to_reach', '')
        if llm_input:
            conditions.append(f"LLM: input needed — {llm_input}")

        # Replace generic hints with LLM's overrepair analysis
        llm_risks = llm_summary.get('overrepair_risks', '')
        if llm_risks:
            hints = [llm_risks] + [h for h in hints if h != 'Unknown — manual review recommended']

    return {
        'schema_version': 'ftfuzz.global_target_context.v1',
        'target_function': func_name,
        'target_location': f'{target_file}:{target_line}',
        'target_state_summary': state_summary,
        'target_function_summary': (
            f'Target at {target_file}:{target_line}'
            + (f' in function {func_name}' if func_name else '')
            + '. See state_summary for code structure details.'
        ),
        'target_relevant_objects': objects,
        'target_relevant_conditions': conditions,
        'target_avoid_overrepair_hints': hints,
        'target_trigger': trigger or {},
        'source': {
            'static_context': snippet_result.get('available', False),
            'llm_summary': bool(llm_summary),
            'manual_override': False,
            'snippet_preview': snippet[:500] if snippet else '(no source available)',
        },
    }


def main():
    p = argparse.ArgumentParser(description='Target Context Builder (generic)')
    p.add_argument('--target-function', required=True, help='Target function name')
    p.add_argument('--target-file-line', required=True, help='Target as file:line')
    p.add_argument('--source-root', required=True, help='Source code root directory')
    p.add_argument('--llm-config', default=None, help='LLM config JSON for semantic summary')
    p.add_argument('--out', required=True, help='Output JSON path')
    args = p.parse_args()

    llm_config = None
    if args.llm_config:
        with open(args.llm_config) as f:
            llm_config = json.load(f)

    target_file, target_line = parse_target_location(args.target_file_line)

    ctx = build_target_context(args.source_root, args.target_function,
                               target_file, target_line, llm_config=llm_config)

    d = os.path.dirname(args.out)
    if d:
        os.makedirs(d, exist_ok=True)

    with open(args.out, 'w') as f:
        json.dump(ctx, f, indent=2)

    print(f'[TARGET_CTX] target={ctx["target_function"]} location={args.target_file_line}')
    print(f'[TARGET_CTX] objects={len(ctx["target_relevant_objects"])} '
          f'conditions={len(ctx["target_relevant_conditions"])} '
          f'hints={len(ctx["target_avoid_overrepair_hints"])}')
    print(f'[OUTPUT] {args.out}')


if __name__ == '__main__':
    main()
