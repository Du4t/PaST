#!/usr/bin/env python3
"""
Runtime-Guided On-Demand Semantic Policy Daemon (Stage 2.1-pre)

Watches online monitor outputs, detects blocked transitions, clusters them,
calls LLM only for representative unresolved clusters, generates policy groups,
and atomically updates policy_store.

Usage:
  # Daemon mode
  python3 inference/semantic_policy_daemon.py \\
      --online-dir /tmp/ftfuzz_online \\
      --source-root /path/to/source \\
      --llm-config configs/llm.example.json \\
      --policy-out policy_store_v2.json \\
      --semantic-cache semantic_cache.json \\
      --interval 30 --daemon

  # One-shot mode
  python3 inference/semantic_policy_daemon.py ... --once
"""

import argparse, json, os, re, sys, time
from datetime import datetime, timezone

ABLATION_MODE = os.environ.get('FTFUZZ_ABLATION', '')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from monitor.blocked_transition_selector import select_blocked
from monitor.transition_clusterer import cluster
from inference.semantic_cache import SemanticCache
from tools.source_context import extract_source_snippet


# ---- Binary format support ----
def _normalize_binary_token(tok):
    """Convert LLM hex notation to actual bytes str. Handles mixed formats:
    'FFD8', '0xFF 0x4F', 'FE//FF//00//1C', odd-length hex, ASCII text."""
    if not tok or not isinstance(tok, str):
        return tok
    # Strip common prefixes, separators, whitespace
    clean = tok.strip().upper()
    # Remove per-segment '0x' / '0X' prefixes
    clean = re.sub(r'\b0X', '', clean)
    # Remove common separators: spaces, commas, colons, slashes, dots
    clean = re.sub(r'[\s,:\/\._-]+', '', clean)
    # Check if the result looks like hex
    if len(clean) >= 2 and all(c in '0123456789ABCDEF' for c in clean):
        # Pad to even length if needed (LLM sometimes miscounts)
        if len(clean) % 2 != 0:
            clean = '0' + clean
        try:
            raw = bytes.fromhex(clean)
            return raw.decode('latin-1')
        except (ValueError, UnicodeDecodeError):
            pass
    return tok


def _fix_json_hex_escapes(json_str):
    """Replace unicode hex escapes (backslash-u-00-HH) with backslash-x-HH for C compat."""
    return re.sub(
        r'\\u00([0-9a-fA-F]{2})',
        lambda m: '\\x{:02x}'.format(int(m.group(1), 16)),
        json_str
    )


def _get_input_format():
    """Read INPUT_FORMAT from env; default 'text'."""
    return os.environ.get('FTFUZZ_INPUT_FORMAT', 'text')


def _build_input_format_guidance(fmt):
    """Generate format-specific guidance for the LLM prompt.

    Returns text appended to the bytecode plan prompt that tells the LLM
    whether the target consumes TEXT or BINARY input and how to adapt its
    bytecode ops accordingly.  Generic — no target-specific logic.
    """
    if fmt == 'text':
        return (
            '\n## INPUT FORMAT — TEXT\n'
            'This target consumes **plain text** (source code, markup, or structured text).\n'
            'The input is a sequence of human-readable characters, NOT raw binary bytes.\n\n'
            '**RULES FOR TEXT INPUT:**\n'
            '1. FIND patterns MUST be **readable text strings**, not hex-encoded bytes.\n'
            '   Write `{"pattern": "function", "output": "kw"}` — NOT `{"pattern": "66756e6374696f6e"}`.\n'
            '   The mutator scans the text buffer for literal text matches.\n'
            '2. WRITE/INSERT data MUST be **plain text strings**, not hex.\n'
            '   Write `{"data": "debug.sethook(function() end)"}` — NOT hex bytes.\n'
            '3. Offset references work on **character boundaries**: `{tag}+5` = 5 characters past the matched tag.\n'
            '4. Think in terms of **tokens and keywords**: Lua keywords (`function`, `end`, `local`),\n'
            '   XML tags (`<root>`, `</root>`), SQL keywords (`CREATE`, `INSERT`, `SELECT`).\n'
            '5. Text structure: use newlines as anchors, insertion before/after tags or tokens.\n'
            '6. PRESERVE protects character ranges — protect magic strings, opening tags, DOCTYPE declarations.\n'
            '7. The scaffold_template should be **valid text** in the target language, not hex.\n'
            '   For Lua: a minimal script like `"local x=1\\nprint(x)\\n"`.\n'
            '   For XML: a well-formed document like `"<?xml version=\\"1.0\\"?><root/>"`.\n'
        ).rstrip()
    else:  # binary
        return (
            '\n## INPUT FORMAT — BINARY\n'
            'This target consumes **binary data** (raw bytes, not text).\n'
            'The input is a sequence of bytes where structure is defined by offsets '
            'and byte values.\n\n'
            '**RULES FOR BINARY INPUT:**\n'
            '1. FIND patterns MUST be **hex-encoded byte sequences** (e.g. `"FFD8"`, `"7f454c46"`).\n'
            '2. WRITE/INSERT data MUST be **hex-encoded bytes** — not plain text.\n'
            '3. SET_INT/INC_INT/SIZE_TO: pay attention to **byte order** (endianness).\n'
            '   Examine format magic bytes for byte-order markers.\n'
            '   Little-endian: least significant byte first.\n'
            '4. SIZE_TO is critical after INSERT/DELETE — fix any length/size fields.\n'
            '5. PRESERVE protects byte ranges — protect magic bytes, headers, checksums.\n'
            '6. Use `scaffold_script` (Python3 with struct.pack) for complex binary '
            'construction.\n'
            '7. NEVER use placeholder strings like `{VERSION}`, `{LENGTH}` — these are '
            'literal bytes.\n'
        ).rstrip()


def atomic_write(path, data):
    tmp = path + '.tmp'
    raw_json = json.dumps(data, indent=2, default=str)
    if _get_input_format() == 'binary':
        raw_json = _fix_json_hex_escapes(raw_json)
    with open(tmp, 'w') as f:
        f.write(raw_json)
    os.replace(tmp, path)


def load_json(path, default=None):
    if not os.path.exists(path): return default
    with open(path) as f:
        raw = f.read()
    # Handle \xHH hex escapes (not standard JSON, but used for binary format)
    # Convert \xHH → \u00HH so Python's json.load can parse it
    raw = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: '\\u00' + m.group(1).upper(), raw)
    return json.loads(raw)


def _build_seed_data_text(tid, seed_buckets):
    """Build a human-readable seed data dump for the LLM prompt."""
    if not seed_buckets:
        return '(no seed data available)'
    transitions = seed_buckets.get('transitions', {})
    buckets = transitions.get(tid, {})
    lines = []
    # Prefer Barrier-Reached seeds (hit the barrier), fall back to any class
    for cls in ('Barrier-Reached', 'Reach-Pre', 'Reach-Post', 'Fail-Pre'):
        seeds = buckets.get(cls, [])[:3]
        if seeds:
            lines.append(f'\n### {cls} seeds ({len(buckets.get(cls, []))} total):')
            for i, s in enumerate(seeds):
                path = s.get('seed_path', '')
                if not path or not os.path.exists(path):
                    continue
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                except Exception:
                    continue
                lines.append(f'\nSeed {i+1} ({len(data)} bytes, path={os.path.basename(path)}):')
                # Hex dump (first 256 bytes)
                hex_str = data[:256].hex()
                lines.append(f'  hex: {hex_str}')
                # If looks like text, show text version
                printable = sum(1 for b in data[:128] if 32 <= b < 127 or b in (9, 10, 13))
                if len(data) > 0 and printable / min(128, len(data)) > 0.7:
                    try:
                        text = data[:256].decode('utf-8', errors='replace')
                        lines.append(f'  text: {text}')
                    except Exception:
                        pass
            break  # Only show one class
    if not lines:
        return '(no seed data available)'
    return '\n'.join(lines)


def call_llm_for_transition(trans, online_context, source_root, llm_config):
    """Call LLM — prefers bytecode_plan.v1 prompt, falls back to relation plan."""
    from tools.precompute_state_semantics import call_llm

    desired_outcome = trans.get('desired_outcome')
    direction_source = trans.get('direction_source', 'unknown')

    # Prefer bytecode_plan.v1 prompt (format-agnostic, 8 opcodes).
    # Fall back to relation_plan.v1 if bytecode prompt is unavailable
    # or if the LLM returns relation_plan format anyway.
    prompt = build_ontology_prompt(trans, source_root)
    result, status = call_llm(prompt, llm_config)

    if result:
        result['semantic_status'] = 'ok'
        result['llm_status'] = 'ok'
        if desired_outcome is not None:
            result['desired_outcome'] = desired_outcome
            result['direction_source'] = direction_source
        schema = result.get('schema_version', '')
        is_new = (schema.startswith('ftfuzz.llm_action_dsl') or
                  schema.startswith('ftfuzz.relation_plan') or
                  schema.startswith('ftfuzz.bytecode_plan'))
        if not is_new:
            if 'semantic_atoms' not in result and 'mechanisms' not in result:
                result = wrap_legacy_result_as_ontology(result, trans)
        return result, status

    # Fallback: legacy precompute prompt (LLM disabled or call failed)
    from tools.precompute_state_semantics import build_llm_prompt
    prompt = build_llm_prompt(trans, source_root)
    result, status = call_llm(prompt, llm_config)
    if result:
        result['semantic_status'] = 'ok'
        result['llm_status'] = 'ok'
        if desired_outcome is not None:
            result['desired_outcome'] = desired_outcome
    return result, status


def build_ontology_prompt(trans, source_root):
    """Build a Bytecode Plan or Relation-Aware LLM prompt.

    Preference: bytecode_plan.v1 (format-agnostic, 8 opcodes).
    Fall back to relation_plan.v1 only if bytecode template is missing.
    """
    pre = trans.get('pre_state', {})
    barrier = trans.get('barrier', {})
    post = trans.get('post_state', {})

    tid = trans.get('transition_id', 'unknown')
    desired = trans.get('desired_outcome')

    from tools.source_context import extract_source_snippet
    barrier_snippet = extract_source_snippet(source_root, barrier.get('file', ''),
                                              barrier.get('line', 0), context_lines=10)

    prompt_dir = os.path.join(os.path.dirname(__file__), '..', 'policy')

    # Try bytecode plan prompt first (PREFERRED — format-agnostic)
    bytecode_prompt_path = os.path.join(prompt_dir, 'bytecode_plan_prompt.md')
    if os.path.exists(bytecode_prompt_path):
        try:
            return _build_bytecode_plan_prompt(trans, source_root, barrier_snippet,
                                                bytecode_prompt_path)
        except Exception as e:
            print(f'[PROMPT] bytecode plan prompt failed: {e}, falling back to relation plan')

    # Try relation-aware prompt (legacy)
    try:
        return _build_relation_plan_prompt(trans, source_root, barrier_snippet)
    except Exception:
        pass

    # Final fallback: Action DSL or ontology prompt
    for template_name in ['relation_aware_planning_prompt.md', 'mutation_ontology_prompt.md']:
        prompt_path = os.path.join(prompt_dir, template_name)
        if os.path.exists(prompt_path):
            with open(prompt_path, 'r') as f:
                template = f.read()
            break
    else:
        template = _default_ontology_prompt()

    barrier_cond_text = 'unknown'
    if barrier_snippet.get('available'):
        for line in barrier_snippet.get('snippet', '').split('\n'):
            if 'if' in line and '(' in line:
                barrier_cond_text = line.strip(); break

    prompt = template
    for k, v in {
        '{transition_id}': tid, '{desired_outcome}': str(desired),
        '{pre_function}': pre.get('function', 'unknown'),
        '{pre_source}': f"{pre.get('file', '')}:{pre.get('line', 0)}",
        '{barrier_function}': barrier.get('function', 'unknown'),
        '{barrier_source}': f"{barrier.get('file', '')}:{barrier.get('line', 0)}",
        '{barrier_condition}': barrier_cond_text,
        '{barrier_type}': barrier.get('type', 'unknown'),
        '{barrier_summary}': barrier_snippet.get('snippet') or '',
        '{distance_true}': str(barrier.get('distance_true', 'unknown')),
        '{distance_false}': str(barrier.get('distance_false', 'unknown')),
        '{post_function}': post.get('function', 'unknown'),
        '{post_source}': f"{post.get('file', '')}:{post.get('line', 0)}",
    }.items():
        prompt = prompt.replace(k, v)
    return prompt


def _extract_barrier_condition(barrier_snippet, barrier_line=0):
    """Extract barrier condition from the barrier's EXACT line number."""
    if not barrier_snippet.get('available'):
        return 'unknown'
    lines = barrier_snippet.get('text', barrier_snippet.get('snippet', '')).split('\n')
    if barrier_line:
        # Find the exact line matching the barrier line number
        line_prefix = f'{barrier_line}:'
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(line_prefix) or str(barrier_line) in stripped[:8]:
                # Extract the condition after the line number
                # Format: "NNNN: \t\tif (condition) ..."
                after_prefix = stripped.split(':', 1)[-1].strip()
                if 'if' in after_prefix:
                    return stripped
    # Fallback: find the line with the barrier's line number
    for line in lines:
        if str(barrier_line) in line[:8] and 'if' in line:
            return line.strip()
    # Last resort: find any if close to the expected position
    for line in lines:
        if 'if' in line and '(' in line:
            return line.strip()
    return 'unknown'


def _derive_desired_outcome(barrier, trans=None):
    """Derive desired_outcome from branch distances when not set in online context."""
    dt = barrier.get('distance_true')
    df = barrier.get('distance_false')
    if dt is not None and df is not None:
        try:
            if float(dt) < float(df):
                return True
            elif float(df) < float(dt):
                return False
        except (ValueError, TypeError):
            pass
    # Try to derive from BB distances in trans data
    if trans:
        try:
            import csv
            dgf_dir = os.environ.get('FTFUZZ_DGF_DIR', '')
            if not dgf_dir:
                ps = os.environ.get('FTFUZZ_POLICY_STORE', '')
                if ps:
                    dgf_dir = os.path.join(os.path.dirname(ps), '..', 'dgf')
            cfg_path = os.path.join(dgf_dir, 'bb_cfg.csv')
            dist_path = os.path.join(dgf_dir, 'bb_distance_full.csv')
            if os.path.exists(cfg_path) and os.path.exists(dist_path):
                # Load distances
                dist = {}
                with open(dist_path) as f:
                    for row in csv.reader(f):
                        if row[0] != 'bb_id':
                            try: dist[int(row[0])] = float(row[1])
                            except: pass
                # Load CFG successors for barrier BB
                state_map_path = os.path.join(dgf_dir, 'state_map_auto.csv')
                barrier_bb = None
                if os.path.exists(state_map_path):
                    with open(state_map_path) as f:
                        for row in csv.reader(f):
                            if row[1] == trans.get('transition_id') and row[2] == 'barrier':
                                barrier_bb = int(row[7])
                                break
                if barrier_bb:
                    successors = set()
                    with open(cfg_path) as f:
                        for row in csv.reader(f):
                            if row[0] != 'src_bb_id' and int(row[0]) == barrier_bb:
                                successors.add(int(row[1]))
                    succ_dists = [(s, dist.get(s, 999)) for s in successors]
                    succ_dists.sort(key=lambda x: x[1])
                    if len(succ_dists) >= 2 and succ_dists[0][1] < succ_dists[1][1]:
                        # first successor = true branch, closer to target
                        return True
        except Exception:
            pass
    return None


def _derive_state_goal(barrier_cond, pre_state, barrier):
    """Derive a meaningful state goal hint from barrier condition and context."""
    # Extract variable names from the condition
    import re
    if barrier_cond and barrier_cond != 'unknown':
        # Find identifiers in the condition
        vars_found = re.findall(r'[a-zA-Z_][a-zA-Z0-9_.>]*', barrier_cond.replace('if', ''))
        vars_found = [v for v in vars_found if len(v) > 1 and v not in ('if', 'else', 'sizeof')]
        if vars_found:
            return f'condition depends on: {", ".join(vars_found[:5])}'
    # Fallback: use function context
    func = barrier.get('function', pre_state.get('function', 'unknown'))
    return f'barrier in {func} — analyze condition to determine controllable input properties'


def _get_post_state_snippet(barrier):
    """Get post-state source snippet (different from pre-state)."""
    return barrier.get('post_snippet', barrier.get('snippet', {}).get('text', '')) if isinstance(barrier.get('snippet'), dict) else ''


def _build_false_branch_guidance(barrier, barrier_cond):
    """Generate guidance for when the FALSE branch must be taken."""
    func = barrier.get('function', 'unknown')
    file = barrier.get('file', '')
    line = barrier.get('line', 0)
    dt = barrier.get('distance_true', '?')
    df = barrier.get('distance_false', '?')
    cond = barrier_cond if barrier_cond != 'unknown' else 'the barrier condition'

    return f"""

## FALSE BRANCH GUIDANCE — Target Requires FALSE Branch

The FALSE branch (distance={df}) is closer to the target than the TRUE branch (distance={dt}).
You MUST generate a plan that makes this barrier condition evaluate to **FALSE**.

**Barrier:** {func} at {file}:{line}
**Condition:** `{cond}`
**Goal:** Make the condition FALSE — i.e., produce input where the condition does NOT hold.

**How to approach this:**
1. Identify which input bytes control the condition's value.
2. Describe an input variant where the condition evaluates to FALSE.
3. If the condition checks a field that can be set to a safe default or omitted entirely, prefer that.
4. Your dictionary_tokens and scaffold_template should reflect the FALSE outcome, not the TRUE one.
5. This is NOT the same as marking the plan unsupported — think about what input properties make the condition false.
"""


def _build_path_to_target(transition_id, cand, source_root):
    """Build a path description from a distant barrier to the target function.

    Uses the callgraph to find the call chain and target context for hints.
    Returns a string describing the path the LLM should try to follow.
    """
    if not cand:
        return '(no path data available)'

    barrier_func = cand.get('barrier', {}).get('function', '?')
    target_func = cand.get('target_function', '')
    # Try to get target from global context
    if not target_func:
        try:
            tc_path = os.environ.get('FTFUZZ_TARGET_CONTEXT', '')
            if tc_path and os.path.exists(tc_path):
                with open(tc_path) as f:
                    tc = json.loads(f.read())
                target_func = tc.get('target_function', '')
                target_summary = tc.get('target_state_summary', '')
        except Exception:
            target_summary = ''

    # Load callgraph to find path
    dgf_dir = os.environ.get('FTFUZZ_DGF_DIR', '/tmp/ftfuzz_dgf')
    cg_path = os.path.join(dgf_dir, 'callgraph.csv')
    callgraph = {}
    if os.path.exists(cg_path):
        with open(cg_path) as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    callgraph.setdefault(parts[0], set()).add(parts[1])

    # BFS from barrier to target in callgraph
    path = []
    if barrier_func in callgraph and target_func:
        visited = {barrier_func: None}
        queue = [barrier_func]
        found = None
        while queue:
            cur = queue.pop(0)
            if cur == target_func:
                found = cur
                break
            for callee in callgraph.get(cur, set()):
                if callee not in visited:
                    visited[callee] = cur
                    queue.append(callee)
        if found:
            # Reconstruct path
            cur = found
            while cur is not None:
                path.append(cur)
                cur = visited[cur]
            path.reverse()

    lines = []
    lines.append(f'You are at barrier: {barrier_func}')
    lines.append(f'Ultimate target: {target_func}')
    if path:
        lines.append(f'Call path to target ({len(path)-1} hops):')
        lines.append(' → '.join(path))
    lines.append(f'\nTarget context: {target_summary[:500] if target_summary else "(see Global Target Context above)"}')
    lines.append('\nYour scaffold MUST produce input that triggers this entire call chain.')
    lines.append('Think about what input format and structure is needed at each step.')

    return '\n'.join(lines)


def _build_bytecode_plan_prompt(trans, source_root, barrier_snippet, prompt_path):
    """Build a bytecode_plan.v1 prompt with seed data and barrier context."""
    with open(prompt_path, 'r') as f:
        template = f.read()

    tid = trans.get('transition_id', 'unknown')
    desired = trans.get('desired_outcome')
    pre_state = trans.get('pre_state', {})
    barrier = trans.get('barrier', {})
    post_state = trans.get('post_state', {})

    active_func = f"{barrier.get('function', '?')}:{barrier.get('file', '?')}:{barrier.get('line', '?')}"
    barrier_cond = barrier.get('condition', {})
    cond_text = barrier_cond.get('kind', 'unknown')
    if barrier_cond.get('predicate'):
        cond_text = f"{barrier_cond['predicate']} ({barrier_cond['kind']})"

    def fmt_state(s):
        if not s: return '(unknown)'
        return f"{s.get('function','?')} at {s.get('file','?')}:{s.get('line','?')}"

    def fmt_goal(t):
        sg = t.get('state_goal', t.get('state_goal_hint', {}))
        if not sg: return '(no state goal available)'
        return str(sg)[:500]

    def fmt_upstream(t):
        ctx = t.get('upstream_context', t.get('upstream_poststate_context', ''))
        if not ctx: return '(no upstream context)'
        return str(ctx)[:2000]

    def fmt_failed(t):
        fa = t.get('failed_actions', t.get('prior_failed_actions', ''))
        if not fa: return '(no prior failed actions)'
        return str(fa)[:1000]

    def fmt_target(t):
        tc = t.get('target_context', t.get('global_target_context', ''))
        if not tc: return '(no target context)'
        return str(tc)[:2000]

    vars_map = {
        '{transition_id}': str(tid),
        '{desired_outcome}': str(desired if desired is not None else 'unknown'),
        '{active_function}': str(pre_state.get('function', '?')) if pre_state.get('function') else str(barrier.get('function', '?')),
        '{active_source}': f"{pre_state.get('file', barrier.get('file', '?'))}:{pre_state.get('line', barrier.get('line', '?'))}",
        '{barrier_condition}': cond_text,
        '{pre_state_summary}': fmt_state(pre_state),
        '{post_state_summary}': fmt_state(post_state),
        '{state_goal_hint}': fmt_goal(trans),
        '{upstream_hops}': str(trans.get('upstream_hops', 0)),
        '{upstream_context}': fmt_upstream(trans),
        '{failed_actions}': fmt_failed(trans),
        '{seed_data}': trans.get('seed_data', '(no seed data available)'),
        '{barrier_summary}': (barrier_snippet.get('snippet') if isinstance(barrier_snippet, dict) else str(barrier_snippet)) or '(no source snippet available)',
        '{target_context}': fmt_target(trans),
        '{input_format_guidance}': _build_input_format_guidance(_get_input_format()),
    }

    prompt = template
    for k, v in vars_map.items():
        if v is None:
            v = '(unknown)'
        prompt = prompt.replace(k, str(v))

    return prompt


def _build_relation_plan_prompt(trans, source_root, barrier_snippet):
    """Build relation-aware prompt with upstream context."""
    tid = trans.get('transition_id', 'unknown')
    desired = trans.get('desired_outcome')
    pre = trans.get('pre_state', {})
    barrier = trans.get('barrier', {})

    # Build upstream context — derive path from source_root
    candidate_path = os.environ.get('FTFUZZ_CANDIDATE_TRANSITIONS',
        os.path.join(source_root.replace('/targets/', '/output/'),
                     'dgf', 'candidate_transitions.refined.json'))
    upstream_text = '(no upstream context available)'
    try:
        from context.upstream_poststate_context_builder import load_candidates, build_transition_graph, select_upstream
        candidates = load_candidates(candidate_path)
        pre_map, post_map, tid_map = build_transition_graph(candidates)
        upstream, quality = select_upstream(tid, tid_map, pre_map, post_map)
        upstream_text = json.dumps([{
            'hop': u['hop'], 'transition_id': u['transition_id'],
            'reason': u.get('selection_reason', ''),
            'state_objects': u.get('state_objects', []),
        } for u in upstream], indent=2)
    except Exception:
        pass

    # Stage 2.7: Load global target context for target-aware planning.
    target_text = '(no target context available)'
    try:
        target_ctx_path = os.environ.get('FTFUZZ_TARGET_CONTEXT', '')
        if not target_ctx_path:
            # Auto-derive: try FTFUZZ_POLICY_STORE → .../policy/ → .../context/global_target_context.json
            ps_path = os.environ.get('FTFUZZ_POLICY_STORE', '')
            if ps_path:
                target_ctx_path = os.path.join(os.path.dirname(ps_path), '..', 'context',
                                               'global_target_context.json')
        if target_ctx_path and os.path.exists(target_ctx_path):
            with open(target_ctx_path) as f:
                target_ctx = json.load(f)
            target_data = {
                'target_function': target_ctx.get('target_function'),
                'target_location': target_ctx.get('target_location'),
                'target_state_summary': target_ctx.get('target_state_summary', ''),
                'target_relevant_objects': target_ctx.get('target_relevant_objects', []),
                'target_relevant_conditions': target_ctx.get('target_relevant_conditions', []),
                'target_avoid_overrepair_hints': target_ctx.get('target_avoid_overrepair_hints', []),
            }
            # Include target_trigger if present (Stage 2.7: precise switch case / branch info)
            trigger = target_ctx.get('target_trigger')
            if trigger and isinstance(trigger, dict) and trigger.get('case_value'):
                target_data['target_trigger'] = trigger
            target_text = json.dumps(target_data, indent=2)
            if len(target_text) > 3000:
                target_text = target_text[:3000] + '\n... (truncated)'
    except Exception as e:
        target_text = f'(error loading target context: {e})'

    # Load template
    prompt_dir = os.path.join(os.path.dirname(__file__), '..', 'policy')
    prompt_path = os.path.join(prompt_dir, 'relation_aware_planning_prompt.md')
    if not os.path.exists(prompt_path):
        raise FileNotFoundError('relation_aware_planning_prompt.md not found')

    with open(prompt_path) as f:
        template = f.read()

    # Extract barrier condition from the barrier's EXACT line
    barrier_cond = _extract_barrier_condition(barrier_snippet, barrier.get('line', 0))
    # Compute desired_outcome from branch distances if not set
    if desired is None:
        desired = _derive_desired_outcome(barrier, trans)

    # Fill template
    prompt = template.replace('{transition_id}', tid)
    prompt = prompt.replace('{desired_outcome}', str(desired))
    prompt = prompt.replace('{active_function}', pre.get('function', 'unknown'))
    prompt = prompt.replace('{active_source}', f"{pre.get('file','')}:{pre.get('line',0)}")
    prompt = prompt.replace('{barrier_condition}', barrier_cond)
    prompt = prompt.replace('{pre_state_summary}', (barrier_snippet.get('snippet') or '')[:400])
    prompt = prompt.replace('{post_state_summary}', _get_post_state_snippet(barrier))
    prompt = prompt.replace('{state_goal_hint}', _derive_state_goal(barrier_cond, pre, barrier))
    prompt = prompt.replace('{upstream_hops}', '3')
    prompt = prompt.replace('{upstream_context}', upstream_text)
    # Read previous scaffold_script error for retry feedback
    failed_text = '(none — first attempt)'
    try:
        err_path = '/tmp/ftfuzz_scaffold_script_error_' + str(os.getpid()) + '.txt'
        if os.path.exists(err_path):
            with open(err_path) as ef:
                err = ef.read().strip()
            if err:
                failed_text = f'Previous scaffold_script FAILED with error:\n{err}\nFix the script to avoid this error.'
            os.remove(err_path)
    except: pass
    prompt = prompt.replace('{failed_actions}', failed_text)
    prompt = prompt.replace('{target_context}', target_text)
    prompt = prompt.replace('{seed_data}', trans.get('seed_data', '(no seed data available)'))

    # Target trigger: add human-readable guidance when target is a specific case/branch
    target_trigger_info = json.loads(target_text).get('target_trigger') if target_text.startswith('{') else None
    if target_trigger_info and isinstance(target_trigger_info, dict):
        if target_trigger_info.get('type') == 'switch_case':
            tv = target_trigger_info.get('case_value', '?')
            tl = target_trigger_info.get('target_line', '?')
            tc = target_trigger_info.get('condition', '')
            prompt += (
                f'\n\n**TARGET TRIGGER — PRECISE GUIDANCE:**\n'
                f'The target at line {tl} is `case {tv}:` inside a switch statement.\n'
                f'To hit the target, the program MUST execute `case {tv}:`, which requires '
                f'the enclosing condition `{tc}` to be TRUE FIRST.\n'
                f'Your scaffold_template MUST produce an input that sets the switch '
                f'variable to exactly {tv}.\n'
            )

    # Binary format hint: tell LLM to use hex-encoded tokens
    if _get_input_format() == 'binary':
        prompt += (
            '\n\n**BINARY FORMAT:** This target consumes BINARY input. '
            'All tokens (precondition_tokens, dictionary_tokens, scaffold_template) '
            'MUST be hex-encoded byte sequences. Use raw hex strings like "FF4F" or '
            '"0xFF 0x4F" for multi-byte sequences. The scaffold_template MUST be a '
            'hex-encoded byte string (e.g., "FF4FFF51" for JPEG-2000 magic). '
            'Do NOT output ASCII text tokens — they will never match binary content.\n'
            '\n**STRONGLY PREFERRED — scaffold_script for binary formats:** '
            'For complex binary formats (ELF, DWARF, etc.), hand-computing hex bytes '
            'often produces broken binaries (wrong offsets, lengths, endianness). '
            'INSTEAD, use the "scaffold_script" field to write a small Python3 script '
            'that constructs the binary using struct.pack(). The script can compute '
            'offsets, lengths, and checksums automatically. '
            'This is FAR more reliable than writing hex bytes by hand.\n'
            '\n**CRITICAL — NO PLACEHOLDERS:** '
            'NEVER use placeholder strings like {VERSION}, {LENGTH}, {OFFSET}, {VALUE}, '
            '{FRESH_ID}, or any other {BRACED} placeholder. The mutator does NOT expand '
            'these — they are treated as literal ASCII bytes and will NEVER match binary '
            'content. EVERY token must be a CONCRETE hex byte sequence representing actual '
            'binary data. If you are unsure about the exact value, use the most common or '
            'default value for the format (e.g., version=0x04 for DWARF4, length=0x0c for '
            'a minimal CU header).\n'
            '\n**CRITICAL — ANCHOR TOKEN (LAST PRECONDITION TOKEN):** '
            'The LAST precondition_token is the INSERTION ANCHOR. The mutator scans the '
            'binary for this exact byte sequence and inserts dictionary_tokens right AFTER '
            'it. The anchor MUST meet ALL of these criteria:\n'
            '1. It must be a CONCRETE byte pattern that ACTUALLY EXISTS in valid seeds\n'
            '2. It must be UNIQUE to the target region (not appear in ELF headers etc.)\n'
            '3. It should be at least 4 bytes long to avoid false matches\n'
            '4. Use bytes from the section HEADER or section NAME that identifies the '
            'target region (e.g., bytes of ".debug_info" section name, not ELF magic)\n'
            'Example: for inserting into .debug_info, use the section name bytes '
            '".debug_info" (2E 64 65 62 75 67 5F 69 6E 66 6F) as anchor, not '
            'the generic \\x02\\x00 which matches everywhere.\n'
            '\n**CRITICAL — BYTE ORDER (ENDIANNESS):** '
            'Many binary formats use LITTLE-ENDIAN byte order where multi-byte values '
            'are stored LSB-first. Before writing any multi-byte value (tags, lengths, '
            'offsets, counts), CHECK the format\'s byte order by examining the format\'s '
            'magic bytes or byte-order marker if present. '
            'For little-endian, write the LEAST significant byte first. '
            'INCORRECT byte order will produce corrupted binary input that fails to parse.\n'
            '\n**CRITICAL — TOKEN MARKER (LAST TOKEN):** '
            'The LAST entry in dictionary_tokens is the INSERTION MARKER. '
            'The mutator searches the existing seed binary for this marker byte sequence, '
            'and inserts all OTHER dictionary tokens BEFORE it. '
            'Choose as marker a structural byte sequence that naturally follows the insertion '
            'point and is likely to exist in valid seeds of this format '
            '(e.g., a next-IFD pointer 00000000, an EOI marker FFD9, or a known trailing tag). '
            'The marker must ACTUALLY EXIST in real seeds — do not invent one.\n'
        )

    # Text format hint: tell LLM to use plain-text tokens, not hex
    elif _get_input_format() == 'text':
        prompt += (
            '\n\n**TEXT FORMAT:** This target consumes TEXT input (source code, markup, or '
            'structured text).\n'
            'All tokens (precondition_tokens, dictionary_tokens, scaffold_template) '
            'MUST be **plain text strings**, not hex-encoded bytes.\n'
            'Use readable keywords, tags, or identifiers as tokens.\n'
            'For Lua: tokens like "function", "local", "end".\n'
            'For XML: tokens like "<root>", "</root>", "<!DOCTYPE".\n'
            'For SQL: tokens like "CREATE", "INSERT", "SELECT".\n'
            'The scaffold_template should be valid text in the target format.'
        )

    # FALSE branch guidance: when target needs the barrier to evaluate to FALSE
    if desired is False:
        prompt += _build_false_branch_guidance(barrier, barrier_cond)

    return prompt


def _default_ontology_prompt():
    """Minimal ontology prompt when template file is unavailable."""
    return """You are a semantic fuzzing policy analyst.
Map program semantics to ontology atoms.

Transition: {transition_id}
Desired outcome: {desired_outcome}

PreState: {pre_summary}
Barrier: {barrier_summary}
PostState: {post_summary}

Output JSON with semantic_atoms array.
"""


def wrap_legacy_result_as_ontology(result, trans):
    """Wrap a legacy free-form LLM result as basic ontology atoms."""
    summary = result.get('barrier_summary', result.get('summary', ''))
    tokens = result.get('dictionary_tokens', [])

    atoms = []
    if tokens:
        # Convert tokens to basic atoms
        if isinstance(tokens, list):
            if isinstance(tokens[0], dict):
                token_strs = [t.get('token', '') for t in tokens]
            else:
                token_strs = [str(t) for t in tokens]
            token_strs = [t for t in token_strs if t]
        else:
            token_strs = []
        if token_strs:
            atoms.append({
                'atom_id': 'A1',
                'source': 'llm_legacy_wrapped',
                'region_role': 'declaration_region',
                'evidence_tokens': token_strs[:10],
                'desired_effect': 'remove_or_forbid',
                'confidence': result.get('confidence', 0.5),
                'rationale': 'Legacy LLM output wrapped as ontology atom',
                'grounding_requirements': ['token_presence'],
            })

    desired = trans.get('desired_outcome')
    return {
        'schema_version': 'ftfuzz.mutation_ontology_atoms.v1',
        'transition_id': trans.get('transition_id', 'unknown'),
        'desired_outcome': desired,
        'semantic_atoms': atoms,
        'non_input_symbols': [],
        'legacy_wrapped': True,
    }



def compile_policy_group(representative, member_tids, semantic_summary, group_id, llm_config,
                         ontology_action_plan=None, action_dsl_plan=None, action_chain=None):
    """Build a policy_group entry matching canonical v2 schema."""
    tc = semantic_summary.get('transition_constraints', {})
    tokens = semantic_summary.get('dictionary_tokens', [])
    if isinstance(tokens, list) and tokens and isinstance(tokens[0], str):
        tokens = [{'token': t, 'source': 'llm'} for t in tokens]

    # Binary format: normalize hex tokens (LLM outputs '0xFF' → actual byte str)
    if _get_input_format() == 'binary':
        tokens = [{'token': _normalize_binary_token(t.get('token', '') if isinstance(t, dict) else str(t)),
                   'source': t.get('source', 'llm') if isinstance(t, dict) else 'llm'}
                  for t in tokens]

    confidence = semantic_summary.get('confidence', 0.5)
    llm_model = llm_config.get('model', semantic_summary.get('model', 'unknown'))
    desired_outcome = semantic_summary.get('desired_outcome')

    # Adjust operator weights when byte-level fields are available
    focus_ranges = semantic_summary.get('focus_ranges', [])
    # Fallback: if focus_ranges is empty but state_goal identifies a byte-level check,
    # synthesize a minimal focus_range from state_goal
    if not focus_ranges:
        state_goal = semantic_summary.get('state_goal', {})
        target = state_goal.get('target', '')
        desired = state_goal.get('desired_state', '')
        if not isinstance(target, str): target = str(target)
        if not isinstance(desired, str): desired = str(desired)
        conf = state_goal.get('confidence', 0.5)
        # Check if state_goal describes a simple byte check (e.g., "azCmd[i][0]" or "first byte")
        import re
        byte_hints = re.findall(r'\[(\d+)\]|byte\s+(\d+)|character\s+(\d+)|first\s+(byte|char)',
                                target + ' ' + desired, re.IGNORECASE)
        if byte_hints and conf > 0.5:
            byte_idx = 0
            for g in byte_hints:
                for v in g:
                    if v and v.isdigit():
                        byte_idx = int(v); break
            focus_ranges = [{
                'start': byte_idx, 'end': byte_idx + 1,
                'role': 'barrier_check_byte',
                'width': 1, 'endian': 'big',
                'confidence': round(conf, 2),
                '_source': 'synthesized_from_state_goal',
            }]

    focus_count = len(focus_ranges)
    numeric_count = len(semantic_summary.get('numeric_fields', []))
    repair_count = len(semantic_summary.get('repair_rules', []))
    has_byte_fields = (focus_count + numeric_count + repair_count) > 0

    group = {
        'group_id': group_id, 'enabled': True,
        'priority': min(1.0, confidence + 0.2), 'confidence': confidence,
        'semantic_source': 'llm', 'llm_model': llm_model,
        'representative_transition': representative,
        'member_transitions': member_tids,
        'desired_outcome': desired_outcome,
        'activation': {
            'state_classes': ['Reach-Pre', 'Blocked-at-Barrier', 'Barrier-Reached'],
            'min_priority': 0.0,
        },
        'semantic_basis': {
            'pre_state_summary': semantic_summary.get('pre_state_summary', {}).get('summary', ''),
            'barrier_summary': semantic_summary.get('barrier_summary', {}).get('summary', ''),
            'post_state_summary': semantic_summary.get('post_state_summary', {}).get('summary', ''),
            'transition_constraints': tc,
        },
        'mutation_actions': {
            'dictionary_tokens': tokens,
            'operator_weights': {
                'dictionary_insert': 0.05, 'fallback_havoc': 0.10,
                'region_focus': 0.30 if has_byte_fields else 0.10,
                'numeric_boundary': 0.25 if has_byte_fields else 0.05,
                'structure_insert': 0.05, 'repair': 0.15 if has_byte_fields else 0.05,
                'dsl_actions': 0.10 if has_byte_fields else 0.50,
                'ontology_actions': 0.00 if has_byte_fields else 0.10,
            },
            'preserve_hints': semantic_summary.get('preserve_ranges', []),
            'focus_hints': focus_ranges,
            'numeric_hints': semantic_summary.get('numeric_fields', []),
            'repair_hints': semantic_summary.get('repair_rules', []),
        },
    }

    if action_chain:
        # Binary format: normalize hex tokens in precondition_tokens.
        # scaffold_template is kept as hex string — the C mutator has
        # hex_decode_scaffold() which auto-detects and decodes hex.
        if _get_input_format() == 'binary':
            pt = action_chain.get('precondition_tokens', [])
            if pt:
                action_chain['precondition_tokens'] = [_normalize_binary_token(t) for t in pt]
            # scaffold_template: keep as hex, do NOT convert to Latin-1

        group['action_chain'] = action_chain
        # PaST-Action ablation: no bytecode steps — boost fallback weights
        if ABLATION_MODE == 'action':
            group['mutation_actions']['operator_weights']['dsl_actions'] = 0.0
            group['mutation_actions']['operator_weights']['dictionary_insert'] = 0.30
            group['mutation_actions']['operator_weights']['fallback_havoc'] = 0.30
        else:
            group['mutation_actions']['operator_weights']['dsl_actions'] = 0.50
            group['mutation_actions']['operator_weights']['dictionary_insert'] = 0.05

        # Stage 2.7: Ensure donor_rebase_policy, preserve_mask_policy defaults
        if 'donor_rebase_policy' not in action_chain:
            action_chain['donor_rebase_policy'] = {
                'enabled': True, 'require_path_relevance': True,
                'max_donor_scan': 5000, 'anchor_satisfaction_weight': 0.3,
                'frontier_survival_weight': 0.2, 'path_relevance_weight': 0.5,
            }
        if 'preserve_mask_policy' not in action_chain:
            action_chain['preserve_mask_policy'] = {
                'enabled': True, 'default_protection': 0,
                'protect_inserted_ranges': True, 'protect_binding_keys': True,
                'max_protected_ratio': 0.35,
            }
        if 'chain_base_selection' not in action_chain:
            action_chain['chain_base_selection'] = {
                'priority': ['current_seed', 'queue_donor', 'llm_scaffold'],
            }
    elif action_dsl_plan:
        group['action_dsl_plan'] = action_dsl_plan
        group['mutation_actions']['operator_weights']['dsl_actions'] = 0.50
        group['mutation_actions']['operator_weights']['dictionary_insert'] = 0.05
    elif ontology_action_plan:
        group['ontology_action_plan'] = ontology_action_plan
        group['mutation_actions']['operator_weights']['dictionary_insert'] = 0.10
        group['mutation_actions']['operator_weights']['ontology_actions'] = 0.40

    return group

def compile_ontology_if_valid(semantic, group_id, online_dir=''):
    """Validate and compile ontology atoms or Action DSL from LLM output.

    Returns an action_chain dict if successful, None otherwise.
    For bytecode_plan.v1: validates and passes through directly (no lowering).
    For relation_plan.v1: lowers effects to opcodes via LOWERING table.
    """
    # Check if LLM output is Action DSL or Relation Plan format
    schema_ver = semantic.get('schema_version', '')
    if schema_ver == 'ftfuzz.bytecode_plan.v1':
        return _compile_bytecode_plan(semantic, group_id, online_dir)
    if schema_ver == 'ftfuzz.relation_plan.v1':
        return _compile_relation_plan(semantic, group_id, online_dir)
    if schema_ver == 'ftfuzz.llm_action_dsl.v1':
        return _compile_action_dsl(semantic, group_id)

    # Fallback: old ontology format
    return _compile_legacy_ontology(semantic, group_id), None


def _target_tmp_path(online_dir, filename):
    """Resolve a target-specific temp file path from online_dir."""
    output_dir = os.path.dirname(online_dir)
    return os.path.join(output_dir, filename)


def _probe_target_with_scaffold(scaffold_bytes, online_dir):
    """Run the fuzz target binary on scaffold bytes, return its output as feedback.
    Derives the target binary path from online_dir -> dgf_dir."""
    import subprocess, tempfile, os as _os, glob as _glob
    dgf_dir = _os.path.join(_os.path.dirname(online_dir), 'dgf')
    if not _os.path.isdir(dgf_dir):
        return ''
    # Find the target binary: largest executable ELF in dgf_dir
    binaries = []
    for f in _os.listdir(dgf_dir):
        fpath = _os.path.join(dgf_dir, f)
        if _os.path.isfile(fpath) and _os.access(fpath, _os.X_OK):
            try:
                with open(fpath, 'rb') as fh:
                    if fh.read(4) == b'\x7fELF':
                        binaries.append((_os.path.getsize(fpath), fpath))
            except Exception:
                pass
    if not binaries:
        return ''
    binaries.sort(reverse=True)
    target_bin = binaries[0][1]

    try:
        with tempfile.NamedTemporaryFile(suffix='.test', delete=False) as tf:
            tf.write(scaffold_bytes)
            tmp_path = tf.name
        # Try multiple invocation patterns, use the first with useful output
        best_out = ''
        for args in ([target_bin, '-nr', tmp_path],
                     [target_bin, '-r', tmp_path],
                     [target_bin, tmp_path]):
            try:
                proc = subprocess.run(args, capture_output=True, timeout=3,
                                      env={**_os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
                out = (proc.stdout + proc.stderr).decode('utf-8', errors='replace')
                # Accept if it looks like real output (not permission/usage errors)
                if len(out) > 20 and 'permission' not in out.lower() and 'usage:' not in out.lower():
                    best_out = out
                    break
            except Exception:
                continue
        _os.unlink(tmp_path)
        return best_out[:600] if best_out else ''
    except Exception:
        return ''


def _inject_scaffold_seed(scaffold_bytes, group_id, online_dir):
    """Write scaffold output as a seed into the AFL++ queue directory.

    Derives the queue directory from online_dir (sibling 'afl_out/default/queue').
    Uses a filename that AFL++ can parse: id:scaffold_XXXXXX,group:PG_XXXX
    """
    import time as _time
    afl_out = os.path.join(os.path.dirname(online_dir), 'afl_out', 'default')
    queue_dir = os.path.join(afl_out, 'queue')
    if not os.path.isdir(queue_dir):
        print(f'[SCAFFOLD_SEED] queue dir not found: {queue_dir}')
        return False
    try:
        ts = int(_time.time() * 1000)
        seed_name = f'id:scaffold_{ts},group:{group_id}'
        seed_path = os.path.join(queue_dir, seed_name)
        with open(seed_path, 'wb') as f:
            f.write(scaffold_bytes)
        print(f'[SCAFFOLD_SEED] injected {len(scaffold_bytes)} bytes as {seed_name}')
        return True
    except Exception as e:
        print(f'[SCAFFOLD_SEED] failed: {e}')
        return False


def _execute_scaffold_script(script, group_id):
    """Execute LLM-generated Python script, capture stdout as bytes.
    Timeout: 5 seconds. Full stdlib access (open() allowed for complex formats).
    Returns bytes on success, None on failure."""
    import subprocess, tempfile, os

    try:
        proc = subprocess.run(
            ['python3', '-c', script],
            capture_output=True, timeout=5, cwd='/tmp',
            env={**os.environ, 'PYTHONPATH': ''}
        )
        if proc.returncode != 0:
            stderr = proc.stderr.decode('utf-8', errors='replace')[:400]
            print(f'[SCAFFOLD_SCRIPT] group={group_id} exit={proc.returncode}: {stderr}')
            # Save error for LLM retry feedback
            try:
                with open('/tmp/ftfuzz_scaffold_script_error_' + str(os.getpid()) + '.txt', 'w') as ef:
                    ef.write(stderr)
            except: pass
            return None
        output = proc.stdout
        if len(output) < 4:
            print(f'[SCAFFOLD_SCRIPT] group={group_id} output too short: {len(output)} bytes')
            return None
        return output
    except subprocess.TimeoutExpired:
        print(f'[SCAFFOLD_SCRIPT] group={group_id} timed out after 5s')
        return None
    except Exception as e:
        print(f'[SCAFFOLD_SCRIPT] group={group_id} error: {e}')
        return None


def _compile_bytecode_plan(semantic, group_id, online_dir=''):
    """Compile LLM bytecode plan (ftfuzz.bytecode_plan.v1) to action chain.

    Bytecode plans are format-agnostic: the LLM outputs opcodes directly
    (FIND, WRITE, INSERT, DELETE, SET_INT, INC_INT, SIZE_TO, PRESERVE).
    No effect→opcode lowering needed — we validate and pass through.

    PaST-Action ablation: skip step compilation entirely. Only inject
    scaffold_template/scaffold_script as seeds.
    """
    if ABLATION_MODE == 'action':
        # PaST-Action: LLM generates complete inputs, no bytecode compilation
        scaffold_text = semantic.get('scaffold_template', '')
        script = semantic.get('scaffold_script', '')
        has_scaffold = bool(scaffold_text) or bool(script)

        if script and isinstance(script, str) and len(script) > 20:
            script_output = _execute_scaffold_script(script, group_id)
            if script_output:
                hex_scaffold = script_output.hex()
                semantic['scaffold_template'] = hex_scaffold
                _inject_scaffold_seed(script_output, group_id, online_dir)
                print(f'[SCAFFOLD_SCRIPT] group={group_id} action-mode: injected {len(script_output)} bytes')
                return {'action_chain': [], 'scaffold_template': hex_scaffold,
                        'precondition_tokens': [], '_action_ablation': True}
        if _get_input_format() == 'text' and scaffold_text and len(str(scaffold_text)) > 4:
            scaffold_bytes = str(scaffold_text).encode('utf-8')
            _inject_scaffold_seed(scaffold_bytes, group_id, online_dir)
            print(f'[SCAFFOLD_TEXT] group={group_id} action-mode: injected {len(scaffold_bytes)} bytes')
            return {'action_chain': [], 'scaffold_template': str(scaffold_text),
                    'precondition_tokens': [], '_action_ablation': True}
        if not has_scaffold:
            print(f'[BYTECODE_COMPILE] group={group_id} action-mode REJECT: no scaffold')
            return None
        return {'action_chain': [], 'scaffold_template': str(scaffold_text) if scaffold_text else '',
                'precondition_tokens': [], '_action_ablation': True}

    try:
        from policy.relation_plan_compiler import compile_bytecode_plan

        chain, errors, report = compile_bytecode_plan(semantic)
        if chain:
            # Execute scaffold_script if present
            script = semantic.get('scaffold_script', '')
            if script and isinstance(script, str) and len(script) > 20:
                script_output = _execute_scaffold_script(script, group_id)
                if script_output:
                    hex_scaffold = script_output.hex()
                    semantic['scaffold_template'] = hex_scaffold
                    chain['scaffold_template'] = hex_scaffold
                    print(f'[SCAFFOLD_SCRIPT] group={group_id} script produced '
                          f'{len(script_output)} bytes (hex-encoded)')
                    _inject_scaffold_seed(script_output, group_id, online_dir)
                else:
                    print(f'[SCAFFOLD_SCRIPT] group={group_id} script execution failed')
                    chain['_scaffold_script_failed'] = True

            # Text format: inject scaffold_template directly as a seed.
            # LLM provides plain-text templates (XML, Lua, SQL); binary
            # format templates are hex-encoded and injected via scaffold_script.
            if _get_input_format() == 'text':
                scaffold_text = semantic.get('scaffold_template', '')
                if scaffold_text and isinstance(scaffold_text, str) and len(scaffold_text) > 4:
                    scaffold_bytes = scaffold_text.encode('utf-8')
                    _inject_scaffold_seed(scaffold_bytes, group_id, online_dir)
                    print(f'[SCAFFOLD_TEXT] group={group_id} injected '
                          f'{len(scaffold_bytes)} bytes as scaffold seed')

            active_steps = sum(
                1 for s in chain.get('action_chain', [])
                if s.get('op') in ('WRITE', 'INSERT', 'DELETE',
                                   'SET_INT', 'INC_INT', 'SIZE_TO'))

            # Require scaffold when there are active steps that need FIND
            # patterns to locate offsets. Without scaffold, seeds that don't
            # already contain the patterns can never execute the chain.
            has_scaffold = bool(chain.get('scaffold_template', ''))
            has_find = any(s.get('op') == 'FIND' for s in chain.get('action_chain', []))
            if has_find and not has_scaffold:
                print(f'[BYTECODE_COMPILE] group={group_id} REJECT: '
                      f'FIND patterns present but no scaffold_template — '
                      f'LLM must provide scaffold to bootstrap seeds')
                return None

            print(f'[BYTECODE_COMPILE] group={group_id} '
                  f'steps={report["step_count"]} active={active_steps} '
                  f'scaffold={len(chain.get("scaffold_template",""))}bytes '
                  f'source=bytecode_plan.v1')
            return chain
        else:
            print(f'[BYTECODE_COMPILE] group={group_id} FAIL: {errors}')
            return None
    except ImportError as e:
        print(f'[BYTECODE_COMPILE] group={group_id} import error: {e}')
        return None
    except Exception as e:
        print(f'[BYTECODE_COMPILE] group={group_id} error: {e}')
        return None


def _compile_relation_plan(semantic, group_id, online_dir=''):
    """Compile LLM relation plan to action chain."""
    try:
        from policy.relation_plan_compiler import compile_relation_plan
        from tools.validate_relation_plan import validate

        ok, errs = validate(semantic)
        if not ok:
            print(f'[REL_PLAN] group={group_id} validation FAIL: {errs[:3]}')
            return None

        chain, errors, report = compile_relation_plan(semantic)
        if chain:
            # Execute scaffold_script FIRST (Stage 2.8): script may produce a valid
            # scaffold even when the ordered_plan has few active steps. The scaffold
            # alone enables the mutator to create seeds that reach the barrier.
            script = semantic.get('scaffold_script', '')
            if script and isinstance(script, str) and len(script) > 20:
                script_output = _execute_scaffold_script(script, group_id)
                if script_output:
                    # Hex-encode binary output so JSON round-trip preserves it.
                    # The mutator's hex_decode_scaffold() will decode it back.
                    hex_scaffold = script_output.hex()
                    semantic['scaffold_template'] = hex_scaffold
                    chain['scaffold_template'] = hex_scaffold
                    print(f'[SCAFFOLD_SCRIPT] group={group_id} script produced '
                          f'{len(script_output)} bytes (hex-encoded for storage)')
                    # Inject scaffold output as a seed into AFL++ queue
                    _inject_scaffold_seed(script_output, group_id, online_dir)
                    # Probe target with scaffold for retry feedback
                    probe_out = _probe_target_with_scaffold(script_output, online_dir)
                    if probe_out:
                        try:
                            probe_path = '/tmp/ftfuzz_scaffold_probe_%s.txt' % group_id
                            with open(probe_path, 'w') as pf:
                                pf.write(probe_out)
                        except Exception:
                            pass
                else:
                    print(f'[SCAFFOLD_SCRIPT] group={group_id} script execution failed')
                    # Signal caller to invalidate cache so LLM retries with fixed script.
                    # The struct.pack/format errors are usually fixable by the LLM.
                    chain['_scaffold_script_failed'] = True

            # Text format: inject scaffold_template directly as a seed
            if _get_input_format() == 'text':
                scaffold_text = semantic.get('scaffold_template', '')
                if scaffold_text and isinstance(scaffold_text, str) and len(scaffold_text) > 4:
                    scaffold_bytes = scaffold_text.encode('utf-8')
                    _inject_scaffold_seed(scaffold_bytes, group_id, online_dir)
                    print(f'[SCAFFOLD_TEXT] group={group_id} injected '
                          f'{len(scaffold_bytes)} bytes as scaffold seed')

            # Reject passive_only chains UNLESS scaffold_script produced bytes
            if report.get('active_steps', 0) == 0 and report.get('step_count', 0) > 0:
                st_len = len(str(chain.get('scaffold_template', '')))
                if st_len < 10:
                    print(f'[REL_COMPILE] group={group_id} REJECTED: passive_only chain '
                          f'(active={report["active_steps"]} passive={report["passive_steps"]}) '
                          f'and no scaffold')
                    return None

            # Reject plans that explicitly acknowledge they cannot reach the target.
            mech_summary = ''
            mech = semantic.get('mechanism', {})
            if isinstance(mech, dict):
                mech_summary = mech.get('summary', '')
            ta = semantic.get('target_alignment', {})
            avoid_actions = ta.get('avoid_actions', []) if isinstance(ta, dict) else []

            bypass_indicators = []
            for text in [mech_summary] + list(avoid_actions):
                if not isinstance(text, str): continue
                text_lower = text.lower()
                if any(kw in text_lower for kw in (
                        'will bypass the target', 'will skip the target',
                        'does not reach the target', 'cannot reach the target',
                        'will prevent reaching', 'diverts execution away from the target')):
                    bypass_indicators.append(text[:120])

            if bypass_indicators:
                print(f'[REL_COMPILE] group={group_id} REJECTED: plan admits '
                      f'cannot reach target — "{bypass_indicators[0]}"')
                return None

            print(f'[REL_COMPILE] group={group_id} steps={report["step_count"]} '
                  f'active={report["active_steps"]} preconditions={report["missing_preconditions_count"]}')
            return chain  # action_chain
        else:
            print(f'[REL_COMPILE] group={group_id} FAIL: {errors}')
            return None
    except ImportError as e:
        print(f'[REL_COMPILE] group={group_id} import error: {e}')
        return None
    except Exception as e:
        print(f'[REL_COMPILE] group={group_id} error: {e}')
        return None


def _compile_action_dsl(semantic, group_id):
    """Compile LLM Action DSL output. Returns (None, dsl_plan) or (None, None)."""
    try:
        from policy.action_dsl_compiler import validate_dsl

        valid, errors, warnings, report = validate_dsl(semantic)
        if not valid:
            print(f'[DSL_VALIDATE] group={group_id} FAIL: {errors[:3]}')
            return None

        accepted = report.get('accepted_actions', [])
        mechanisms = [a for a in accepted if a.get('type') == 'mechanism_accepted']
        n_rej = len(report.get('rejected_actions', []))
        print(f'[DSL_COMPILE] group={group_id} mechanisms={len(mechanisms)} '
              f'rejected={n_rej} compiler_added_semantics=false')

        if not mechanisms:
            print(f'[DSL_COMPILE] group={group_id} all mechanisms rejected')
            return None

        return semantic  # Return raw DSL (compiler only validates, doesn't transform)
    except ImportError as e:
        print(f'[DSL_COMPILE] group={group_id} import error: {e}')
        return None
    except Exception as e:
        print(f'[DSL_COMPILE] group={group_id} error: {e}')
        return None


def _compile_legacy_ontology(semantic, group_id):
    """Compile old ontology atoms format."""
    try:
        from policy.ontology_atom_validator import validate_atoms
        from policy.ontology_policy_compiler import compile_ontology_atoms, load_capabilities

        valid, errors, warnings, _ = validate_atoms(semantic)
        if not valid:
            print(f'[ONTO_VALIDATE] group={group_id} FAIL: {errors[:3]}')
            return None

        caps_path = os.path.join(os.path.dirname(__file__), '..',
                                 'policy', 'mutator_capabilities.json')
        capabilities = load_capabilities(caps_path)
        action_plan, report = compile_ontology_atoms(semantic, capabilities)

        if report['actions_compiled'] == 0 and report['actions_rejected'] > 0:
            print(f'[ONTO_COMPILE] group={group_id} all actions rejected: '
                  f'{report["rejection_reasons"]}')
            if not semantic.get('legacy_wrapped'):
                return None

        return action_plan
    except ImportError as e:
        print(f'[ONTO_COMPILE] group={group_id} import error: {e}')
        return None
    except Exception as e:
        print(f'[ONTO_COMPILE] group={group_id} error: {e}')
        return None


def _apply_decay(tid, blocked_list, decay_weights):
    """Apply DECAY_FACTOR to a barrier's weight after LLM failure."""
    for b in blocked_list:
        if b['transition_id'] == tid:
            init_score = b.get('rank_score', b.get('blocked_score', 0.5))
            old_w = decay_weights.get(tid, init_score)
            decay_weights[tid] = old_w * 0.8
            break


def run_once(online_dir, source_root, llm_config, policy_out, cache_path,
             top_k_blocked=20, max_llm_per_round=3):
    # Preload candidate transitions for fallback context (unreached barriers)
    candidate_tid_map = {}
    candidate_path = os.environ.get('FTFUZZ_CANDIDATE_TRANSITIONS',
        os.path.join(os.path.dirname(online_dir), 'dgf', 'candidate_transitions.refined.json'))
    try:
        if os.path.exists(candidate_path):
            candidates_raw = load_json(candidate_path, {})
            for t in candidates_raw.get('transitions', []):
                candidate_tid_map[t.get('transition_id', '')] = t
    except Exception:
        pass

    ctx = load_json(os.path.join(online_dir, 'online_transition_runtime_context.json'), {})
    stsr = load_json(os.path.join(online_dir, 'online_stsr.json'), {})
    seed_buckets = load_json(os.path.join(online_dir, 'online_seed_buckets.json'), {})
    ranking = load_json(os.path.join(online_dir, 'online_barrier_ranking.json'),
                        {'ranked_transitions': []})

    if not ctx.get('transitions') and not ranking.get('ranked_transitions'):
        # No runtime observations at all — try loading candidates directly
        if candidate_tid_map:
            # Build a minimal ranking from candidate data for the unreached
            # barrier fallback to process.
            cand_ranking = []
            for tid, c in candidate_tid_map.items():
                r = c.get('ranking', {})
                b = c.get('barrier', {})
                cand_ranking.append({
                    'transition_id': tid,
                    'score': r.get('priority', 0),
                    'distance_to_target': r.get('distance_post', 999),
                    'distance_true': b.get('distance_true', 999),
                    'distance_false': b.get('distance_false', 999),
                    'pre_count': 0,
                    'barrier_count': 0,
                    'post_count': 0,
                    'stsr': 0,
                })
            cand_ranking.sort(key=lambda x: -x['score'])
            ranking = {'ranked_transitions': cand_ranking}
            print(f'[DAEMON] No sidecar data — synthesized ranking from '
                  f'{len(cand_ranking)} candidate transitions')
        else:
            print('[DAEMON] No online transition context or candidates — skipping')
            return None

    cache = SemanticCache(cache_path, never_invalidate=(ABLATION_MODE == 'feedback'))
    llm_enabled = llm_config.get('enabled', False)

    # Check for scaffold stale signals from mutator (Stage 2.8 retry)
    # Mutator writes /tmp/ftfuzz_scaffold_retry_<group_id> when threshold reached.
    # PaST-Feedback ablation: skip — one-shot policy, no retry.
    if ABLATION_MODE != 'feedback':
        found_signal = False
        for gid in list(cache.data.get('entries', {}).keys()) + ['PG_0001']:
            sig_path = '/tmp/ftfuzz_scaffold_retry_%s' % gid
            if os.path.exists(sig_path):
                found_signal = True
                try:
                    os.remove(sig_path)
                except Exception:
                    pass
        if found_signal:
            # Read old scaffold_script BEFORE invalidation
            old_script = ''
            entries = cache.data.get('entries', {})
            for sig_key in entries:
                entry = entries.get(sig_key, {})
                summary = entry.get('summary', {})
                old_script = summary.get('scaffold_script', '')
                if old_script:
                    break
            # Now invalidate
            for sig_key in list(entries.keys()):
                cache.invalidate_entry(sig_key, 'scaffold_stale_no_progress')
            print('[DAEMON] Scaffold retry signal detected — invalidating cache for fresh LLM plan')
            # Write feedback: target probe output + old script
            try:
                with open('/tmp/ftfuzz_scaffold_script_error_' + str(os.getpid()) + '.txt', 'w') as ef:
                    ef.write('Fix the scaffold_script below. The resulting binary did NOT '
                             'improve distance to target.\n\n')
                    probe = ''
                    try:
                        probe_path = '/tmp/ftfuzz_scaffold_probe_%s.txt' % gid
                        with open(probe_path, 'r') as pf:
                            probe = pf.read().strip()
                    except Exception:
                        pass
                    if probe:
                        ef.write('=== TARGET OUTPUT ===\n%s\n\n' % probe)
                    ef.write('=== PREVIOUS FAILED SCRIPT (fix it) ===\n')
                    ef.write(old_script if old_script else '(not found)')
                print('[DAEMON] Retry feedback written: script=%d chars probe=%d chars' % (
                    len(old_script or ''), len(probe or '')))
            except Exception as e:
                print('[DAEMON] Failed to write retry feedback: %s' % e)

    # Step 1: Select blocked
    blocked = select_blocked(ctx, stsr, ranking, top_k=top_k_blocked)
    blocked_list = blocked.get('blocked_transitions', [])

    # ── Filter dead_end barriers ──
    # Barriers where the state_map has post bb_id = -1 can never be crossed
    # because runtime instrumentation cannot record post_hit for an unknown BB.
    # Load state_map to find dead_end barriers.
    dead_end_set = set()
    state_map_path = os.environ.get('FTFUZZ_STATE_MAP',
        os.path.join(os.path.dirname(online_dir), 'dgf', 'state_map_auto.csv'))
    try:
        if os.path.exists(state_map_path):
            with open(state_map_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 7 and parts[2] == 'post' and parts[-1] == '-1':
                        dead_end_set.add(parts[1])  # transition_id
    except Exception:
        pass
    before = len(blocked_list)
    if dead_end_set:
        blocked_list = [b for b in blocked_list if b['transition_id'] not in dead_end_set]
        if len(blocked_list) < before:
            print(f'[DAEMON] Filtered {before - len(blocked_list)} dead_end barriers')

    # ── Per-round barrier failure tracking ──
    # barrier_failures tracks consecutive LLM failures per barrier within
    # this daemon round. Clears each call to run_once().
    barrier_failures = {}
    EXHAUST_AFTER = 3  # consecutive failures before skipping this round

    # ── Mixed selection: supplement blocked with unreached close barriers ──
    # When blocked_list is smaller than top_k_blocked, fill remaining slots
    # from unreached barriers (bar=0) that are close to the target and not
    # dead_end.  This gives LLM a chance to generate scaffolds for barriers
    # that are near the target but have never been reached.
    ranked = ranking.get('ranked_transitions', [])
    if len(blocked_list) < top_k_blocked and ranked:
        existing_tids = {b['transition_id'] for b in blocked_list}
        # Unreached: bar=0, not dead_end, close to target
        unreached = []
        for r in ranked:
            tid = r['transition_id']
            if tid in existing_tids:
                continue
            if tid in dead_end_set:
                continue
            if r.get('barrier_count', 0) > 0:
                continue  # already reached
            dist = r.get('distance_to_target', 999)
            if dist < 999:
                unreached.append((dist, r))
        unreached.sort(key=lambda x: x[0])  # closest to target first

        needed = top_k_blocked - len(blocked_list)
        for dist, r in unreached[:needed]:
            tid = r['transition_id']
            blocked_list.append({
                'transition_id': tid,
                'pre_count': r.get('pre_count', 0),
                'barrier_count': r.get('barrier_count', 0),
                'post_count': r.get('post_count', 0),
                'is_blocked': False,
                'distance_to_target': r.get('distance_to_target', 999),
                'distance_true': r.get('distance_true'),
                'distance_false': r.get('distance_false'),
                'blocked_score': r.get('score', 0),
                'rank_score': r.get('score', 0),
                'unreached_mixed': True,
            })
        if needed > 0 and len(blocked_list) > before:
            added = len(blocked_list) - before
            print(f'[DAEMON] Supplemented {added} unreached close barriers to '
                  f'top-{len(blocked_list)}')

    # ── Distance-bucket decay weights (persist across daemon cycles) ──
    # Each barrier's weight starts at its ranking score. When LLM fails to
    # break through (post still 0), weight *= DECAY_FACTOR. When post>0,
    # weight resets to initial ranking score. Weights only affect selection
    # *within* the same distance_to_target bucket.
    DECAY_FACTOR = 0.8

    if not hasattr(run_once, '_decay_weights'):
        run_once._decay_weights = {}  # tid -> float
    decay_weights = run_once._decay_weights

    # Update decay weights based on STSR data from this cycle:
    # - post>0 → barrier broken → reset weight
    # - selected last cycle but post still 0 → apply decay
    stsr_trans = stsr.get('transitions', {})
    for tid in list(decay_weights.keys()):
        st = stsr_trans.get(tid, {})
        if st.get('post_count', 0) > 0:
            del decay_weights[tid]  # barrier broken, reset to original score
        else:
            # Still blocked — persist decay for next bucket competition
            pass

    # Apply decay weights to blocked barriers within each distance bucket.
    # Barriers at the same distance compete via probability-based selection.
    if blocked_list and ranked:
        # Separate blocked (is_blocked=True) from unreached (is_blocked=False)
        blocked_only = [b for b in blocked_list if b.get('is_blocked', True)]
        unreached_only = [b for b in blocked_list if not b.get('is_blocked', True)]

        if blocked_only:
            # Group by distance_to_target
            buckets = {}
            for b in blocked_only:
                dist = int(b.get('distance_to_target', 999))
                buckets.setdefault(dist, []).append(b)

            # Within each bucket, apply decay weights and probability sample
            import random
            decayed_blocked = []
            for dist, items in buckets.items():
                if len(items) <= 1:
                    decayed_blocked.extend(items)
                    continue
                # Assign weights: ranking score * decay factor
                weights = []
                for b in items:
                    tid = b['transition_id']
                    init_score = b.get('rank_score', b.get('blocked_score', 0.5))
                    w = decay_weights.get(tid, init_score)
                    weights.append(max(w, 0.01))  # floor to prevent zero
                # Probability-based ordering within bucket.
                # Items with higher weight appear earlier (more likely to be
                # in the top slots when selected by the cluster step).
                # Use weighted shuffle: sort by -random.expovariate(weight)
                # which gives a probability-proportional ordering without
                # replacement.
                shuffled = sorted(items,
                    key=lambda b: -random.expovariate(
                        1.0 / max(decay_weights.get(b['transition_id'],
                            b.get('rank_score', b.get('blocked_score', 0.5))), 0.01)))
                decayed_blocked.extend(shuffled)

            blocked_list = decayed_blocked + unreached_only

    # ── Failure backoff: skip exhausted barriers ──
    # Per-round exhaustion: a barrier is exhausted when LLM has failed
    # EXHAUST_AFTER consecutive times on it this round.  Exhaustion resets
    # next round so new seed data can enable better LLM output.
    # Tracked in barrier_failures dict, checked during LLM loop below.
    # (The actual backoff check is done before each LLM call — see Step 3)
    if not blocked_list:
        # Fallback: no barrier has been reached yet (all bar=0).
        # Pick the best UNREACHED barriers from the ranking for LLM to
        # generate a scaffold that might reach them.  Prefer barriers
        # with a large distance gap between true/false branches (meaningful
        # decisions) that are close to the target.
        ranked = ranking.get('ranked_transitions', [])
        if ranked:
            # Score unreached barriers: prefer branch_edge transitions with
            # meaningful distance gaps between true/false successors.
            # -1.0 means "unreachable via that branch" — treat as no-data (999).
            # Only transitions where BOTH branches have valid (>=0) distances
            # and the gap is large enough are scored.
            scored = []
            for r in ranked:
                true_d = r.get('distance_true')
                false_d = r.get('distance_false')
                # Treat -1 (unreachable) as no-data
                td = true_d if (true_d is not None and true_d >= 0) else 999
                fd = false_d if (false_d is not None and false_d >= 0) else 999
                if td < 900 and fd < 900:
                    gap = abs(td - fd)
                    if gap >= 5.0:
                        dist = r.get('distance_to_target', 999)
                        score = gap / max(dist, 1.0)
                        scored.append((score, r))
            scored.sort(key=lambda x: -x[0])

            # Synthesize a minimal blocked-list entry for each top candidate
            synthesized = []
            for score, r in scored[:top_k_blocked]:
                tid = r['transition_id']
                # Build a synthetic transition context from the ranking data
                trans_ctx = ctx.get('transitions', {}).get(tid, {})
                synthesized.append({
                    'transition_id': tid,
                    'pre_count': r.get('pre_count', 0),
                    'barrier_count': r.get('barrier_count', 0),
                    'post_count': r.get('post_count', 0),
                    'is_blocked': False,  # unreached — needs LLM scaffold to reach
                    'distance_to_target': r.get('distance_to_target', 999),
                    'distance_true': r.get('distance_true'),
                    'distance_false': r.get('distance_false'),
                    'blocked_score': r.get('score', 0),
                    'rank_score': r.get('score', 0),
                    'unreached_fallback': True,
                })

            if synthesized:
                blocked_list = synthesized
                # Patch summary for downstream logging
                blocked['summary']['blocked_count'] = len(synthesized)
                blocked['summary']['top_k'] = len(synthesized)
                blocked['summary']['fallback_unreached'] = True
                print(f'[DAEMON] No blocked transitions — falling back to '
                      f'top-{len(blocked_list)} unreached barriers with '
                      f'largest distance gaps')
            else:
                # Second fallback: no barriers reached AND no gap-scored
                # barriers. Pick the barriers with LARGEST distance to target
                # (closest to entry point / earliest in call chain). These are
                # the most likely to be reachable by the current seed frontier.
                # Ask LLM to generate scaffold that bridges from current reach
                # toward these early barriers, then progressively inward.
                ranked = ranking.get('ranked_transitions', [])
                if ranked:
                    # Sort by distance_to_target descending (largest = closest to entry)
                    farthest = sorted(ranked,
                                      key=lambda r: r.get('distance_to_target', 0),
                                      reverse=True)
                    synthesized = []
                    for r in farthest[:top_k_blocked]:
                        tid = r['transition_id']
                        synthesized.append({
                            'transition_id': tid,
                            'pre_count': r.get('pre_count', 0),
                            'barrier_count': r.get('barrier_count', 0),
                            'post_count': r.get('post_count', 0),
                            'is_blocked': False,
                            'distance_to_target': r.get('distance_to_target', 999),
                            'distance_true': r.get('distance_true'),
                            'distance_false': r.get('distance_false'),
                            'blocked_score': r.get('score', 0),
                            'rank_score': r.get('score', 0),
                            'unreached_fallback': True,
                            'farthest_fallback': True,
                        })
                    if synthesized:
                        blocked_list = synthesized
                        blocked['summary']['blocked_count'] = len(synthesized)
                        blocked['summary']['top_k'] = len(synthesized)
                        blocked['summary']['fallback_farthest'] = True
                        print(f'[DAEMON] No reachable barriers — falling back '
                              f'to top-{len(blocked_list)} farthest barriers '
                              f'(closest to entry, largest distance to target)')
                    else:
                        print('[DAEMON] No blocked transitions and no '
                              'unreached barriers — skipping')
                        print(f'[STATUS] LLM enabled={llm_enabled} '
                              f'cache_size={cache.stats()["total"]} groups=0')
                        return None
                else:
                    print('[DAEMON] No blocked transitions and no ranking '
                          'data — skipping')
                    print(f'[STATUS] LLM enabled={llm_enabled} cache_size={cache.stats()["total"]} groups=0')
                    return None
        else:
            print('[DAEMON] No blocked transitions detected')
            print(f'[STATUS] LLM enabled={llm_enabled} cache_size={cache.stats()["total"]} groups=0')
            return None

    print(f'[DAEMON] {blocked["summary"]["blocked_count"]} blocked transitions, '
          f'top-{len(blocked_list)} scored')

    # Step 2: Cluster — inject decay weights into blocked_score so that
    # cluster_best_score naturally picks the decay-favored representative.
    if decay_weights:
        for b in blocked_list:
            tid = b['transition_id']
            if tid in decay_weights:
                b['blocked_score'] = decay_weights[tid]
    reps = cluster(blocked_list, ctx)
    clusters = reps.get('clusters', [])
    print(f'[DAEMON] {len(clusters)} clusters from {len(blocked_list)} blocked')

    # Step 3: LLM for representatives (within budget)
    llm_calls = 0
    cache_hits = 0
    policy_groups = {}
    t2pg = {}

    llm_model_used = llm_config.get('model', 'none')

    for cl in clusters[:max_llm_per_round]:
        rep_tid = cl['representative_transition']
        sig = cl['signature']
        members = cl['member_transitions']
        group_id = cl['cluster_id'].replace('CL_', 'PG_')
        semantic = None  # reset per iteration

        # Check cache with validation
        cached = cache.lookup(sig)
        if cached:
            valid, reason = cache.is_entry_valid({'summary': cached})
            if valid:
                cache_hits += 1
                semantic = cached
                cache.mark_used(sig)
                # Merge desired_outcome from online context
                trans_ctx = ctx.get('transitions', {}).get(rep_tid, {})
                branch_dir = trans_ctx.get('branch_direction', {})
                if branch_dir.get('available') and branch_dir.get('desired_outcome') is not None:
                    if 'desired_outcome' not in semantic or semantic['desired_outcome'] is None:
                        semantic['desired_outcome'] = branch_dir['desired_outcome']
                        semantic['direction_source'] = branch_dir.get('direction_source', 'unknown')
                print(f'[CACHE] hit for {rep_tid} (cluster {group_id})')
            else:
                cache.invalidate_entry(sig, f'empty_cache_{reason}')
                print(f'[SEM_CACHE] invalid entry transition={rep_tid} reason={reason}')

        if semantic is None and llm_enabled and llm_calls < max_llm_per_round:
            # ── Failure backoff: skip exhausted barriers this round ──
            if barrier_failures.get(rep_tid, 0) >= EXHAUST_AFTER:
                print(f'[LLM_SKIP] {rep_tid} exhausted ({barrier_failures[rep_tid]} '
                      f'consecutive failures) — skipping this round')
                continue

            llm_calls += 1
            trans_ctx = ctx.get('transitions', {}).get(rep_tid, {})
            branch_dir = trans_ctx.get('branch_direction', {})
            trans_data = {
                'transition_id': rep_tid,
                'pre_state': trans_ctx.get('pre_state', {}),
                'barrier': trans_ctx.get('barrier', {}),
                'post_state': trans_ctx.get('post_state', {}),
            }
            # Fallback: use candidate transition data when online context
            # is empty (unreached barriers, no runtime observation yet)
            cand = candidate_tid_map.get(rep_tid, {})
            if not trans_data['pre_state'] and cand.get('pre_state'):
                trans_data['pre_state'] = cand['pre_state']
            if not trans_data['barrier'] and cand.get('barrier'):
                trans_data['barrier'] = cand['barrier']
            if not trans_data['post_state'] and cand.get('post_state'):
                trans_data['post_state'] = cand['post_state']
            if branch_dir.get('available') and branch_dir.get('desired_outcome') is not None:
                trans_data['desired_outcome'] = branch_dir['desired_outcome']
                trans_data['direction_source'] = branch_dir.get('direction_source', 'unknown')
                print(f'[DIRECTION] {rep_tid} desired={branch_dir["desired_outcome"]} '
                      f'source={branch_dir.get("direction_source")} '
                      f'true_dist={branch_dir.get("distance_true")} '
                      f'false_dist={branch_dir.get("distance_false")}')
            elif not trans_data.get('desired_outcome') and cand.get('ranking', {}).get('distance_post') is not None:
                # Synthesize desired_outcome from candidate distance data
                true_d = cand.get('barrier', {}).get('distance_true', 999)
                false_d = cand.get('barrier', {}).get('distance_false', 999)
                if true_d is not None and false_d is not None and true_d >= 0 and false_d >= 0:
                    trans_data['desired_outcome'] = true_d < false_d
                    trans_data['direction_source'] = 'candidate_static'

            # Inject seed data for byte-level field identification
            trans_data['seed_data'] = _build_seed_data_text(rep_tid, seed_buckets)

            # For farthest-fallback barriers: add path context to help LLM
            # understand how to reach the target from this distant barrier.
            # All blocked_list items from farthest fallback have the flag set.
            if blocked.get('summary', {}).get('fallback_farthest') or \
               blocked.get('summary', {}).get('fallback_unreached'):
                trans_data['upstream_context'] = _build_path_to_target(
                    rep_tid, cand, source_root)

            print(f'[LLM_WAIT] calling LLM for {rep_tid} (attempt {barrier_failures.get(rep_tid,0)+1})...')
            result, status = call_llm_for_transition(trans_data, ctx, source_root, llm_config)
            if result:
                context_hash = f'{rep_tid}_{int(time.time())}'
                cache.store(sig, context_hash, result, llm_model_used,
                            result.get('confidence', 0.5),
                            desired_outcome=trans_data.get('desired_outcome'),
                            prompt_schema_version=result.get('schema_version', 'ftfuzz.mutation_ontology.v1'),
                            ontology_schema_version='ftfuzz.mutation_ontology.v1')
                semantic = result
                if result.get('schema_version') == 'ftfuzz.bytecode_plan.v1':
                    print(f'[LLM] call transition={rep_tid} desired_outcome={trans_data.get("desired_outcome")} '
                          f'steps={len(result.get("steps",[]))} '
                          f'focus={len(result.get("focus_ranges",[]))} '
                          f'preserve={len(result.get("preserve_ranges",[]))} '
                          f'schema=bytecode_plan.v1')
                else:
                    print(f'[LLM] call transition={rep_tid} desired_outcome={trans_data.get("desired_outcome")} '
                          f'atoms={len(result.get("semantic_atoms",[]))} '
                          f'tokens={len(result.get("dictionary_tokens",[]))} '
                          f'focus={len(result.get("focus_ranges",[]))} '
                          f'numeric={len(result.get("numeric_fields",[]))} '
                          f'preserve={len(result.get("preserve_ranges",[]))}')
            else:
                print(f'[LLM] failed for {rep_tid}: {status}')
                barrier_failures[rep_tid] = barrier_failures.get(rep_tid, 0) + 1
                _apply_decay(rep_tid, blocked_list, decay_weights)
                continue

            # LLM returned a result — check if it's a usable plan
            steps = result.get('steps', [])
            if not steps:
                barrier_failures[rep_tid] = barrier_failures.get(rep_tid, 0) + 1
                _apply_decay(rep_tid, blocked_list, decay_weights)
            else:
                barrier_failures[rep_tid] = 0  # reset on valid plan

        if semantic is None:
            print(f'[SKIP] {rep_tid}: no valid cache, LLM disabled/budget exceeded')
            continue

        # Step 4: Build policy group with ontology/DSL compilation
        ontology_plan = None
        dsl_plan = None
        action_chain = None
        schema_ver = semantic.get('schema_version', '')

        if schema_ver == 'ftfuzz.bytecode_plan.v1':
            # Bytecode plan → action chain (preferred: format-agnostic, no lowering)
            action_chain = compile_ontology_if_valid(semantic, group_id, online_dir)
            if action_chain:
                n_steps = len(action_chain.get('action_chain', []))
                active = sum(1 for s in action_chain.get('action_chain', [])
                             if s.get('op') in ('WRITE', 'INSERT', 'DELETE',
                                                'SET_INT', 'INC_INT', 'SIZE_TO'))
                print(f'[BYTECODE_COMPILE] group={group_id} transition={rep_tid} '
                      f'steps={n_steps} active={active} '
                      f'desired={semantic.get("desired_outcome")}')
                if action_chain.get('_scaffold_script_failed'):
                    cache.invalidate_entry(sig, 'scaffold_script_failed')
                barrier_failures[rep_tid] = 0  # compile success
            else:
                print(f'[BYTECODE_COMPILE] group={group_id} validation/compilation failed')
                barrier_failures[rep_tid] = barrier_failures.get(rep_tid, 0) + 1
                _apply_decay(rep_tid, blocked_list, decay_weights)
                cache.invalidate_entry(sig, 'bytecode_plan_failed')
        elif schema_ver == 'ftfuzz.relation_plan.v1':
            action_chain = compile_ontology_if_valid(semantic, group_id, online_dir)
            if action_chain:
                print(f'[REL_COMPILE] group={group_id} transition={rep_tid} '
                      f'steps={len(action_chain.get("action_chain",[]))} '
                      f'desired={semantic.get("desired_outcome")}')
                if action_chain.get('_scaffold_script_failed'):
                    cache.invalidate_entry(sig, 'scaffold_script_failed')
                barrier_failures[rep_tid] = 0
            else:
                print(f'[REL_COMPILE] group={group_id} validation/compilation failed')
                barrier_failures[rep_tid] = barrier_failures.get(rep_tid, 0) + 1
                _apply_decay(rep_tid, blocked_list, decay_weights)
                cache.invalidate_entry(sig, 'relation_plan_failed')
        elif schema_ver == 'ftfuzz.llm_action_dsl.v1':
            dsl_plan = compile_ontology_if_valid(semantic, group_id, online_dir)
            if dsl_plan:
                print(f'[DSL_COMPILE] group={group_id} mechanisms={len(dsl_plan.get("mechanisms",[]))}')
                barrier_failures[rep_tid] = 0
            else:
                barrier_failures[rep_tid] = barrier_failures.get(rep_tid, 0) + 1
                cache.invalidate_entry(sig, 'dsl_validation_failed')
        elif ('semantic_atoms' in semantic and semantic.get('semantic_atoms')):
            ontology_plan = compile_ontology_if_valid(semantic, group_id, online_dir)
            if ontology_plan:
                n_atoms = len(semantic.get('semantic_atoms', [])); print(f'[ONTO_COMPILE] group={group_id} atoms={n_atoms}')
                barrier_failures[rep_tid] = 0
            else:
                barrier_failures[rep_tid] = barrier_failures.get(rep_tid, 0) + 1
                cache.invalidate_entry(sig, 'validation_failed')

        group = compile_policy_group(rep_tid, members, semantic, group_id, llm_config,
                                     ontology_action_plan=ontology_plan,
                                     action_dsl_plan=dsl_plan,
                                     action_chain=action_chain)
        policy_groups[group_id] = group
        for tid in members:
            t2pg[tid] = group_id

    # Step 5: Build and write policy_store (merge old action_chains)
    store_version = 1
    old_store = load_json(policy_out)
    if old_store:
        store_version = old_store.get('store_version', 0) + 1
        # Merge old action_chains into new groups (preserve LLM plans across cycles)
        old_groups = old_store.get('policy_groups', {})
        for gid, new_group in policy_groups.items():
            old_group = old_groups.get(gid, {})
            old_ac = old_group.get('action_chain')
            new_ac = new_group.get('action_chain')
            if old_ac and not new_ac:
                new_group['action_chain'] = old_ac
            elif old_ac and new_ac:
                # Preserve old scaffold if new one is empty
                if not new_ac.get('scaffold_template') and old_ac.get('scaffold_template'):
                    new_ac['scaffold_template'] = old_ac['scaffold_template']
                    new_group['action_chain'] = new_ac
        # Also keep old groups that weren't updated in this cycle
        for gid, old_group in old_groups.items():
            if gid not in policy_groups:
                policy_groups[gid] = old_group

    store = {
        'schema_version': 'ftfuzz.policy_store.v2',
        'store_version': store_version,
        'updated_at_unix_ms': int(time.time() * 1000),
        'updated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'activation_mode': 'seed_state_conditioned',
        'metadata': {
            'generated_by': 'semantic_policy_daemon.py',
            'semantic_source_mode': 'runtime_guided_on_demand',
            'llm_enabled': llm_enabled,
            'llm_model': llm_config.get('model', 'none'),
            'llm_calls_total': llm_calls,
            'cache_hits_total': cache_hits,
        },
        'policy_groups': policy_groups,
        'transition_to_policy_group': t2pg,
        'policies': {},  # legacy compat — not the primary path
        'compatibility': {
            'legacy_policies_present': False,
            'single_active_policy_present': False,
        },
    }
    atomic_write(policy_out, store)

    status = {
        'blocked_count': len(blocked_list),
        'clusters': len(clusters),
        'llm_calls': llm_calls,
        'cache_hits': cache_hits,
        'policy_groups': len(policy_groups),
        'store_version': store_version,
    }
    print(f'[STATUS] groups={status["policy_groups"]} llm_calls={llm_calls} '
          f'cache_hits={cache_hits} store_v{store_version}')
    return status


def run_daemon(online_dir, source_root, llm_config, policy_out, cache_path,
               interval=30, top_k_blocked=20, max_llm_per_round=3):
    print(f'[DAEMON] Starting, interval={interval}s, online_dir={online_dir}')
    while True:
        try:
            run_once(online_dir, source_root, llm_config, policy_out,
                     cache_path, top_k_blocked, max_llm_per_round)
        except Exception as e:
            print(f'[DAEMON] Error: {e}')
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser(description='Semantic Policy Daemon')
    p.add_argument('--online-dir', required=True)
    p.add_argument('--source-root', required=True)
    p.add_argument('--llm-config', default=None)
    p.add_argument('--policy-out', required=True)
    p.add_argument('--semantic-cache', default='/tmp/ftfuzz_semantic_cache.json')
    p.add_argument('--interval', type=int, default=30)
    p.add_argument('--top-k-blocked', type=int, default=20)
    p.add_argument('--max-llm-calls-per-round', type=int, default=3)
    p.add_argument('--daemon', action='store_true')
    p.add_argument('--once', action='store_true')
    args = p.parse_args()

    llm_config = load_json(args.llm_config, {'enabled': False}) if args.llm_config else {'enabled': False}

    if args.daemon:
        run_daemon(args.online_dir, args.source_root, llm_config, args.policy_out,
                   args.semantic_cache, args.interval, args.top_k_blocked,
                   args.max_llm_calls_per_round)
    else:
        run_once(args.online_dir, args.source_root, llm_config, args.policy_out,
                 args.semantic_cache, args.top_k_blocked, args.max_llm_calls_per_round)


if __name__ == '__main__':
    main()
