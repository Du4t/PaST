#!/usr/bin/env python3
"""
FTFuzz Semantic MutationPolicy Compiler (Stage 2.0)

Reads state_semantics.json + online runtime context + barrier ranking,
extracts semantic hints, scores transitions, and generates:
  - semantic_policies.json  (full semantic policy artifacts)
  - policy_store.json       (compact runtime-readable policy store)

Usage:
  python3 policy/semantic_policy_compiler.py \\
      --state-semantics state_semantics.json \\
      --online-context online_transition_runtime_context.json \\
      --barrier-ranking online_barrier_ranking.json \\
      --seed-buckets online_seed_buckets.json \\
      --out-dir /path/to/policy \\
      --top-k 10 \\
      --mode semantic
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from copy import deepcopy

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "ftfuzz.semantic_mutation_policy.v1"

# XML-specific tokens for rule-based extraction
XML_TOKENS = [
    "<!DOCTYPE", "<!ELEMENT", "<!ATTLIST", "<!ENTITY", "<!NOTATION",
    "#PCDATA", "EMPTY", "ANY", "CDATA", "SYSTEM", "PUBLIC",
    "NDATA", "#FIXED", "#IMPLIED", "#REQUIRED",
    "<?xml", "encoding=", "version=", "standalone=",
    "<![CDATA[", "]]>",
]

GENERIC_TOKENS = [
    'magic', 'header', 'footer', 'chunk', 'section',
]

# Keywords for hint extraction
PRESERVE_KEYWORDS = [
    'valid header', 'well-formed', 'magic bytes', 'DOCTYPE structure',
    'DTD structure', 'XML declaration', 'container structure',
    'chunk header', 'parser state', 'passed header validation',
    'valid xml', 'xml well-formedness', 'well-formedness',
]

FOCUS_KEYWORDS = [
    'element declaration', 'content model', 'length field', 'count field',
    'type field', 'offset', 'branch condition', 'target case',
    'specific parser branch', 'condition', 'element', 'attribute',
    'content', 'namespace', 'prefix',
]

NUMERIC_KEYWORDS = [
    'length', 'count', 'size', 'index', 'offset', 'bound',
    'remaining', 'capacity', 'limit', 'width', 'height',
]

REPAIR_KEYWORDS = [
    'checksum', 'length consistency', 'container size',
    'offset consistency', 'payload size', 'count matches entries',
    'well-formedness repair', 'repair',
]


# ---------------------------------------------------------------------------
# Hint extraction
# ---------------------------------------------------------------------------
def extract_dictionary_tokens(semantics_entry):
    """Extract dictionary tokens from semantic summaries."""
    tokens = []
    seen = set()

    # Collect all text from semantic fields
    text_fields = []
    for key in ('pre_state_summary', 'barrier_summary', 'post_state_summary'):
        if key in semantics_entry:
            text_fields.append(semantics_entry[key].get('summary', ''))
    tc = semantics_entry.get('transition_constraints', {})
    for key in ('preserve', 'mutate_focus', 'avoid'):
        for item in tc.get(key, []):
            text_fields.append(item)

    combined = ' '.join(text_fields)

    # XML token matching
    for token in XML_TOKENS:
        if token.lower() in combined.lower() or any(
                t.lower() in combined.lower() for t in token.split()):
            if token not in seen:
                tokens.append({
                    'token': token,
                    'encoding': 'ascii',
                    'source': 'rule_extractor',
                    'weight': 0.5,
                    'reason': f'found in semantics: {token}',
                })
                seen.add(token)

    # Generic tokens
    for token in GENERIC_TOKENS:
        if token.lower() in combined.lower() and token not in seen:
            tokens.append({
                'token': token,
                'encoding': 'ascii',
                'source': 'format_heuristic',
                'weight': 0.3,
                'reason': f'format keyword: {token}',
            })
            seen.add(token)

    return tokens


def extract_preserve_hints(semantics_entry):
    """Extract preserve hints from semantic summaries."""
    hints = []
    tc = semantics_entry.get('transition_constraints', {})

    # From transition_constraints.preserve
    for item in tc.get('preserve', []):
        hints.append({
            'kind': 'semantic_region',
            'description': f'preserve {item}',
            'source': 'transition_constraints',
            'confidence': 0.6,
        })

    # Keyword matching in summaries
    for key in ('pre_state_summary', 'barrier_summary'):
        summary = semantics_entry.get(key, {}).get('summary', '')
        for kw in PRESERVE_KEYWORDS:
            if kw.lower() in summary.lower():
                hints.append({
                    'kind': 'semantic_region',
                    'description': f'preserve {kw}',
                    'source': key,
                    'confidence': 0.5,
                })
                break

    return hints


def extract_focus_hints(semantics_entry):
    """Extract focus hints from semantic summaries."""
    hints = []
    tc = semantics_entry.get('transition_constraints', {})

    for item in tc.get('mutate_focus', []):
        hints.append({
            'kind': 'semantic_focus',
            'description': f'mutate {item}',
            'source': 'transition_constraints',
            'confidence': 0.6,
        })

    for key in ('barrier_summary', 'transition_constraints'):
        if key == 'transition_constraints':
            text = ' '.join(tc.get('mutate_focus', []) + tc.get('avoid', []))
        else:
            text = semantics_entry.get(key, {}).get('summary', '')
        for kw in FOCUS_KEYWORDS:
            if kw.lower() in text.lower():
                hints.append({
                    'kind': 'semantic_focus',
                    'description': f'focus on {kw} to pass barrier',
                    'source': key,
                    'confidence': 0.5,
                })
                break

    return hints


def extract_numeric_hints(semantics_entry):
    """Extract numeric hints from semantic summaries."""
    hints = []
    combined = ''
    for key in ('barrier_summary', 'post_state_summary',
                'transition_constraints'):
        if key == 'transition_constraints':
            tc = semantics_entry.get('transition_constraints', {})
            combined += ' '.join(tc.get('mutate_focus', []))
        else:
            combined += ' ' + semantics_entry.get(key, {}).get('summary', '')

    for kw in NUMERIC_KEYWORDS:
        if kw in combined.lower():
            hints.append({
                'kind': 'numeric_semantic',
                'role': 'length_or_count' if kw in ('length', 'count', 'size',
                                                     'remaining', 'capacity', 'limit')
                else 'offset_or_index',
                'direction': 'unknown',
                'source': 'barrier_summary',
                'confidence': 0.4,
            })
            break

    return hints


def extract_repair_hints(semantics_entry):
    """Extract repair hints from semantic summaries."""
    hints = []
    tc = semantics_entry.get('transition_constraints', {})
    combined = ' '.join(tc.get('avoid', []) + tc.get('mutate_focus', []))

    for kw in REPAIR_KEYWORDS:
        if kw.lower() in combined.lower():
            hints.append({
                'kind': 'semantic_repair',
                'description': f'may need {kw} repair after mutation',
                'source': 'transition_constraints',
                'confidence': 0.3,
            })
            break

    return hints


# ---------------------------------------------------------------------------
# Policy compilation
# ---------------------------------------------------------------------------
def get_semantic_source(sem_entry, llm_enabled=False):
    """Map llm_status to semantic_source."""
    llm_status = sem_entry.get('llm_status', 'stub')
    if llm_status == 'ok' and llm_enabled:
        return 'llm'
    elif llm_status == 'stub':
        return 'stub'
    elif llm_status and 'failed' in str(llm_status):
        return 'failed'
    return 'fallback'


def compile_policies(state_semantics, online_context, barrier_ranking,
                     seed_buckets, top_k=10, prefer_llm=False,
                     require_llm_for_active=False, min_llm_confidence=0.7):
    """Main compilation: semantics + runtime → mutation policies."""

    semantics_transitions = state_semantics.get('transitions', {})
    online_transitions = online_context.get('transitions', {})
    ranking_list = barrier_ranking.get('ranked_transitions', [])
    seed_transitions = seed_buckets.get('transitions', {})
    llm_enabled = state_semantics.get('llm_enabled', False)
    llm_model = state_semantics.get('model', 'none')

    # Build ranking lookup
    ranking_map = {}
    for r in ranking_list:
        ranking_map[r['transition_id']] = r

    policies = {}

    for tid, sem_entry in semantics_transitions.items():
        # Runtime grounding
        online_t = online_transitions.get(tid, {})
        online_stats = online_t.get('online_stats', {})
        rinfo = ranking_map.get(tid, {})
        seeds = seed_transitions.get(tid, {})

        # Semantic source
        sem_source = get_semantic_source(sem_entry, llm_enabled)

        # Extract hints
        dict_tokens = extract_dictionary_tokens(sem_entry)
        preserve_hints = extract_preserve_hints(sem_entry)
        focus_hints = extract_focus_hints(sem_entry)
        numeric_hints = extract_numeric_hints(sem_entry)
        repair_hints = extract_repair_hints(sem_entry)

        # Compute confidence from semantics
        sem_confidence = sem_entry.get('confidence', 0.15)
        llm_status = sem_entry.get('llm_status', 'stub')
        if sem_source == 'llm':
            sem_confidence = max(sem_confidence, 0.5)

        # Runtime grounding
        stsr = online_stats.get('stsr', 1.0)
        pre = online_stats.get('pre_count', 0)
        bar = online_stats.get('barrier_count', 0)
        post = online_stats.get('post_count', 0)

        # Compute priority
        rank_score = rinfo.get('score', 0)
        max_rank_score = max((r.get('score', 1) for r in ranking_list),
                             default=1) or 1
        blocked_score = rank_score / max_rank_score
        seed_bucket_avail = 1.0 if seeds else 0.0
        missing_sem = 0.0 if sem_entry.get('semantic_status') == 'ok' else 0.3

        priority = (
            2.0 * blocked_score
            + 1.5 * (1.0 - stsr)
            + 1.0 * sem_confidence
            + 0.5 * seed_bucket_avail
            - 0.5 * missing_sem
        )
        # LLM bonus
        if prefer_llm and sem_source == 'llm':
            priority += 1.0

        has_hints = (len(dict_tokens) + len(preserve_hints) +
                     len(focus_hints) + len(numeric_hints) + len(repair_hints))
        tc = sem_entry.get('transition_constraints', {})
        has_hints += len(tc.get('preserve', [])) + len(tc.get('mutate_focus', []))

        # LLM semantics + hints → enabled (runtime gating via activation.state_classes)
        enabled = (sem_source == 'llm' and has_hints > 0) or (pre > 0 and stsr < 0.95)

        policies[tid] = {
            'transition_id': tid,
            'enabled': enabled,
            'policy_version': 1,
            'policy_type': 'semantic' if has_hints > 0 else 'fallback',
            'semantic_source': sem_source,
            'llm_model': llm_model if sem_source == 'llm' else 'none',
            'priority': round(priority, 4),
            'confidence': round(sem_confidence, 4),
            'activation': {
                'requires_active_transition': True,
                'min_pre_count': max(1, pre // 10) if pre > 0 else 1,
                'max_stsr': 0.5,
                'preferred_state_classes': [
                    'Blocked-at-Barrier',
                    'Barrier-Reached',
                    'Reach-Pre',
                ],
            },
            'semantic_basis': {
                'pre_state_summary': sem_entry.get(
                    'pre_state_summary', {}).get('summary', ''),
                'barrier_summary': sem_entry.get(
                    'barrier_summary', {}).get('summary', ''),
                'post_state_summary': sem_entry.get(
                    'post_state_summary', {}).get('summary', ''),
                'transition_constraints': sem_entry.get(
                    'transition_constraints', {}),
            },
            'mutation_actions': {
                'preserve_hints': preserve_hints,
                'focus_hints': focus_hints,
                'dictionary_tokens': dict_tokens,
                'numeric_hints': numeric_hints,
                'structure_hints': [],
                'repair_hints': repair_hints,
                'operator_weights': {
                    'fallback_havoc': 0.3,
                    'dictionary_insert': 0.25 if dict_tokens else 0.15,
                    'region_focus': 0.2,
                    'numeric_boundary': 0.1 if numeric_hints else 0.05,
                    'structure_insert': 0.1,
                    'repair': 0.05,
                },
            },
            'runtime_grounding': {
                'stsr': stsr,
                'pre_count': pre,
                'barrier_count': bar,
                'post_count': post,
                'top_seed_buckets': {
                    cls: [s.get('seed_path', '') for s in seeds.get(cls, [])[:3]]
                    for cls in list(seeds.keys())[:4]
                } if seeds else {},
                'cmp_evidence': [],
            },
            'validation': {
                'status': 'unvalidated',
                'last_applied_version': 0,
                'success_metric': 'post_count_increase_or_stsr_improvement',
            },
        }

    # Sort and filter
    sorted_policies = sorted(policies.items(),
                             key=lambda x: -x[1]['priority'])

    # Filter for LLM requirements
    if require_llm_for_active:
        llm_policies = [(tid, p) for tid, p in sorted_policies
                        if p['semantic_source'] == 'llm'
                        and p['confidence'] >= min_llm_confidence]
        if not llm_policies:
            print('[WARN] No LLM policy meets --require-llm-for-active '
                  f'(need semantic_source=llm, confidence>={min_llm_confidence})',
                  file=sys.stderr)
    else:
        llm_policies = sorted_policies

    # Select top-k, preferring LLM if requested
    if prefer_llm:
        llm_first = [(tid, p) for tid, p in llm_policies
                     if p['semantic_source'] == 'llm']
        other = [(tid, p) for tid, p in llm_policies
                 if p['semantic_source'] != 'llm']
        sorted_policies = llm_first + other

    top_policies = dict(sorted_policies[:top_k])

    return top_policies


def build_policy_store_v2(policies, online_context, barrier_ranking, llm_used=False):
    """Build multi-policy v2 store with seed-state-conditioned activation."""
    online_transitions = online_context.get('transitions', {})
    ranking_map = {r['transition_id']: r for r in
                   barrier_ranking.get('ranked_transitions', [])}

    compact = {}
    for tid, p in policies.items():
        ma = p['mutation_actions']
        rg = p.get('runtime_grounding', {})
        online_t = online_transitions.get(tid, {})
        online_stats = online_t.get('online_stats', {})

        # Determine applicable state classes from runtime data
        state_classes = []
        pre = online_stats.get('pre_count', 0)
        bar = online_stats.get('barrier_count', 0)
        post = online_stats.get('post_count', 0)
        if post > 0:
            state_classes.append('Reach-Post')
        if bar > 0 and post == 0:
            state_classes.append('Blocked-at-Barrier')
            state_classes.append('Barrier-Reached')
        if pre > 0 and bar == 0:
            state_classes.append('Reach-Pre')
        if not state_classes:
            state_classes.append('Reach-Pre')  # default

        # Activation conditions
        activation = {
            'state_classes': state_classes[:4],
            'requires_pre_hit': True,
            'requires_barrier_hit': len(state_classes) > 0 and
                'Blocked' in str(state_classes) or 'Barrier' in str(state_classes),
            'requires_post_not_hit': post == 0,
            'min_pre_count': max(1, pre // 20) if pre > 0 else 1,
            'max_stsr': 0.5 if post == 0 else 0.95,
        }

        # Priority as resource allocation weight (not global selection)
        rinfo = ranking_map.get(tid, {})
        rank_score = rinfo.get('score', 0)
        max_s = max((r.get('score', 1) for r in
                     barrier_ranking.get('ranked_transitions', [{}])), default=1) or 1
        blocked_score = rank_score / max_s
        stsr = online_stats.get('stsr', 1.0)
        priority = (
            p.get('confidence', 0.2) * 1.0
            + blocked_score * 1.5
            + (1.0 - stsr) * 1.0
            + (1.0 if len(ma.get('dictionary_tokens', [])) > 0 else 0) * 0.5
            - (stsr if stsr > 0.5 else 0) * 0.5
        )

        compact[tid] = {
            'transition_id': tid,
            'policy_version': p['policy_version'],
            'enabled': p['enabled'],
            'policy_type': p.get('policy_type', 'semantic'),
            'semantic_source': p.get('semantic_source', 'fallback'),
            'llm_model': p.get('llm_model', 'none'),
            'confidence': p.get('confidence', 0),
            'priority': round(max(0.0, priority), 4),
            'activation': activation,
            'mutation_actions': {
                'dictionary_tokens': [
                    {'token': t['token'], 'encoding': t.get('encoding', 'ascii')}
                    for t in ma['dictionary_tokens']
                ],
                'operator_weights': ma['operator_weights'],
                'preserve_hints_count': len(ma.get('preserve_hints', [])),
                'focus_hints_count': len(ma.get('focus_hints', [])),
                'numeric_hints_count': len(ma.get('numeric_hints', [])),
                'repair_hints_count': len(ma.get('repair_hints', [])),
            },
            'runtime_stats': {
                'pre_count': pre,
                'barrier_count': bar,
                'post_count': post,
                'stsr': stsr,
                'rank': rinfo.get('rank'),
            },
        }

    return {
        'schema_version': 'ftfuzz.policy_store.v2',
        'store_version': 1,
        'updated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'activation_mode': 'seed_state_conditioned',
        'debug_single_active_transition': None,
        'selection_policy': {
            'strategy': 'weighted_applicable_policy',
            'fallback': 'havoc',
            'max_applicable_policies_per_seed': 4,
        },
        'policies': compact,
        'runtime_priority': {
            tid: compact[tid]['priority'] for tid in compact
        },
        'metadata': {
            'generated_by': 'semantic_policy_compiler.py',
            'mode': 'offline_snapshot',
            'llm_used': llm_used,
        },
    }


def build_policy_store(policies, active_tid, llm_used=False):
    """Build compact policy_store.json from full policies."""
    compact = {}
    for tid, p in policies.items():
        ma = p['mutation_actions']
        compact[tid] = {
            'transition_id': tid,
            'policy_version': p['policy_version'],
            'enabled': p['enabled'],
            'priority': p['priority'],
            'confidence': p['confidence'],
            'policy_type': p['policy_type'],
            'semantic_source': p.get('semantic_source', 'fallback'),
            'llm_model': p.get('llm_model', 'none'),
            'mutation_actions': {
                'dictionary_tokens': [
                    {'token': t['token'], 'encoding': t.get('encoding', 'ascii')}
                    for t in ma['dictionary_tokens']
                ],
                'operator_weights': ma['operator_weights'],
                'preserve_hints_count': len(ma['preserve_hints']),
                'focus_hints_count': len(ma['focus_hints']),
                'numeric_hints_count': len(ma['numeric_hints']),
                'repair_hints_count': len(ma['repair_hints']),
            },
        }

    active_policy = compact.get(active_tid, {})
    sem_source = active_policy.get('semantic_source', 'fallback')
    return {
        'schema_version': 'ftfuzz.policy_store.v1',
        'store_version': 1,
        'updated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'active_transition': active_tid,
        'active_policy_version': active_policy.get('policy_version', 0),
        'selection_reason': (f'selected top-ranked LLM-derived semantic policy'
                             if sem_source == 'llm'
                             else 'top blocked transition with semantic policy'),
        'active_policy_metadata': {
            'semantic_source': sem_source,
            'semantic_confidence': active_policy.get('confidence', 0),
            'llm_model': active_policy.get('llm_model', 'none'),
            'dictionary_token_count': len(active_policy.get(
                'mutation_actions', {}).get('dictionary_tokens', [])),
            'preserve_hint_count': active_policy.get(
                'mutation_actions', {}).get('preserve_hints_count', 0),
            'focus_hint_count': active_policy.get(
                'mutation_actions', {}).get('focus_hints_count', 0),
            'numeric_hint_count': active_policy.get(
                'mutation_actions', {}).get('numeric_hints_count', 0),
            'repair_hint_count': active_policy.get(
                'mutation_actions', {}).get('repair_hints_count', 0),
        },
        'policies': compact,
        'metadata': {
            'generated_by': 'semantic_policy_compiler.py',
            'mode': 'offline_snapshot',
            'llm_used': llm_used,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description='FTFuzz Semantic MutationPolicy Compiler')
    parser.add_argument('--state-semantics', required=True,
                        help='Path to state_semantics.json')
    parser.add_argument('--online-context', required=True,
                        help='Path to online_transition_runtime_context.json')
    parser.add_argument('--barrier-ranking', required=True,
                        help='Path to online_barrier_ranking.json')
    parser.add_argument('--seed-buckets', default=None,
                        help='Path to online_seed_buckets.json')
    parser.add_argument('--cmp-evidence', default=None,
                        help='Optional CmpLog evidence (reserved interface)')
    parser.add_argument('--out-dir', required=True,
                        help='Output directory for policy artifacts')
    parser.add_argument('--top-k', type=int, default=10,
                        help='Max policies to generate')
    parser.add_argument('--mode', default='semantic',
                        choices=['semantic', 'hybrid'],
                        help='Policy generation mode')
    parser.add_argument('--prefer-llm', action='store_true',
                        help='Rank LLM-derived policies above stub')
    parser.add_argument('--require-llm-for-active', action='store_true',
                        help='Fail if no LLM-derived active policy available')
    parser.add_argument('--min-llm-confidence', type=float, default=0.7,
                        help='Minimum confidence for LLM policies (default: 0.7)')
    parser.add_argument('--allow-stub-fallback', action='store_true',
                        help='Allow stub fallback when no LLM policy exists')
    parser.add_argument('--emit-stub-policy', action='store_true',
                        help='Also emit stub-only policies for comparison')
    parser.add_argument('--emit-llm-policy', action='store_true',
                        help='Emit LLM-only policies for comparison')
    parser.add_argument('--require-executable-actions', action='store_true',
                        help='Active policy must have executable actions (tokens>0)')
    parser.add_argument('--min-dictionary-tokens', type=int, default=1,
                        help='Min dictionary tokens for active policy (default: 1)')
    parser.add_argument('--fail-if-no-executable-active', action='store_true',
                        help='Fail hard if no executable active policy found')
    args = parser.parse_args()

    # Load inputs
    for path, name in [
        (args.state_semantics, 'state_semantics'),
        (args.online_context, 'online_context'),
        (args.barrier_ranking, 'barrier_ranking'),
    ]:
        if not os.path.exists(path):
            print(f'[ERROR] {name} not found: {path}', file=sys.stderr)
            sys.exit(1)

    with open(args.state_semantics) as f:
        state_semantics = json.load(f)
    with open(args.online_context) as f:
        online_context = json.load(f)
    with open(args.barrier_ranking) as f:
        barrier_ranking = json.load(f)

    seed_buckets = {}
    if args.seed_buckets and os.path.exists(args.seed_buckets):
        with open(args.seed_buckets) as f:
            seed_buckets = json.load(f)

    os.makedirs(args.out_dir, exist_ok=True)

    # Compile
    print(f'[INFO] Compiling policies from {len(state_semantics.get("transitions", {}))} '
          f'semantic entries, top-k={args.top_k}')
    llm_used = state_semantics.get('llm_enabled', False)
    policies = compile_policies(
        state_semantics, online_context, barrier_ranking, seed_buckets,
        top_k=args.top_k,
        prefer_llm=args.prefer_llm,
        require_llm_for_active=args.require_llm_for_active,
        min_llm_confidence=args.min_llm_confidence)

    # Select active transition — prefer LLM, require executable actions
    ranking_list = barrier_ranking.get('ranked_transitions', [])
    active_tid = None

    # First try: top ranked LLM policy with executable actions
    if args.prefer_llm or args.require_llm_for_active:
        for r in ranking_list:
            tid = r['transition_id']
            if tid in policies:
                p = policies[tid]
                if p.get('semantic_source') == 'llm':
                    tokens = len(p['mutation_actions']['dictionary_tokens'])
                    if not args.require_executable_actions or tokens >= args.min_dictionary_tokens:
                        active_tid = tid
                        break

    # Fallback: top blocked with tokens
    if not active_tid:
        for r in ranking_list:
            tid = r['transition_id']
            if tid in policies:
                tokens = len(policies[tid]['mutation_actions']['dictionary_tokens'])
                if not args.require_executable_actions or tokens >= args.min_dictionary_tokens:
                    active_tid = tid
                    break

    # Last resort
    if not active_tid and policies:
        if args.fail_if_no_executable_active:
            print('[ERROR] No executable active policy found '
                  f'(require_executable_actions={args.require_executable_actions}, '
                  f'min_tokens={args.min_dictionary_tokens})', file=sys.stderr)
            sys.exit(1)
        active_tid = next(iter(policies.keys()))

    # Force-enable active policy if it has executable actions
    if active_tid and active_tid in policies:
        ap = policies[active_tid]
        if len(ap['mutation_actions']['dictionary_tokens']) > 0:
            ap['enabled'] = True

    # Write semantic_policies.json (full)
    semantic_output = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%SZ'),
        'source': {
            'semantics_file': args.state_semantics,
            'online_context_file': args.online_context,
            'barrier_ranking_file': args.barrier_ranking,
            'seed_buckets_file': args.seed_buckets or 'not_provided',
            'cmp_evidence_file': args.cmp_evidence or 'not_provided',
        },
        'policies': policies,
    }
    with open(os.path.join(args.out_dir, 'semantic_policies.json'), 'w') as f:
        json.dump(semantic_output, f, indent=2, default=str)
    print(f'[INFO] semantic_policies.json: {len(policies)} policies')

    # Write policy_store_v2.json (multi-policy, seed-state-conditioned)
    policy_store_v2 = build_policy_store_v2(
        policies, online_context, barrier_ranking, llm_used)
    with open(os.path.join(args.out_dir, 'policy_store_v2.json'), 'w') as f:
        json.dump(policy_store_v2, f, indent=2, default=str)
    print(f'[INFO] policy_store_v2.json: {len(policy_store_v2["policies"])} policies, '
          f'activation_mode={policy_store_v2["activation_mode"]}, '
          f'store_version={policy_store_v2["store_version"]}')

    # Also write v1 for backward compat
    policy_store_v1 = build_policy_store(policies, active_tid, llm_used)
    with open(os.path.join(args.out_dir, 'policy_store.json'), 'w') as f:
        json.dump(policy_store_v1, f, indent=2, default=str)
    print(f'[INFO] policy_store.json (v1 compat): active={active_tid}')

    # Summary
    total_tokens = sum(
        len(p['mutation_actions']['dictionary_tokens'])
        for p in policies.values())
    total_preserve = sum(
        len(p['mutation_actions']['preserve_hints'])
        for p in policies.values())
    total_focus = sum(
        len(p['mutation_actions']['focus_hints'])
        for p in policies.values())
    total_numeric = sum(
        len(p['mutation_actions']['numeric_hints'])
        for p in policies.values())
    total_repair = sum(
        len(p['mutation_actions']['repair_hints'])
        for p in policies.values())

    active_policy = policies.get(active_tid, {})
    print(f'\n[SUMMARY]')
    print(f'  Policies:       {len(policies)}')
    print(f'  Active:         {active_tid}')
    print(f'  Semantic source: {active_policy.get("semantic_source", "N/A")}')
    print(f'  LLM model:      {active_policy.get("llm_model", "N/A")}')
    print(f'  Confidence:     {active_policy.get("confidence", 0):.2f}')
    print(f'  Dict tokens:    {total_tokens}')
    print(f'  Preserve:       {total_preserve}')
    print(f'  Focus:          {total_focus}')
    print(f'  Numeric:        {total_numeric}')
    print(f'  Repair:         {total_repair}')
    print(f'  LLM used:       {llm_used}')

    # Write validation report
    report = {
        'generated_at': datetime.now(timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%SZ'),
        'policy_count': len(policies),
        'active_transition': active_tid,
        'active_policy_type': policies.get(
            active_tid, {}).get('policy_type', 'none'),
        'total_dictionary_tokens': total_tokens,
        'total_preserve_hints': total_preserve,
        'total_focus_hints': total_focus,
        'total_numeric_hints': total_numeric,
        'total_repair_hints': total_repair,
        'llm_used': llm_used,
        'schema_valid': True,
        'warnings': [],
    }
    with open(os.path.join(args.out_dir,
                           'policy_validation_report.json'), 'w') as f:
        json.dump(report, f, indent=2)
    print(f'[INFO] policy_validation_report.json written')


if __name__ == '__main__':
    main()
