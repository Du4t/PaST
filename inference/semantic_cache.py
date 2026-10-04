#!/usr/bin/env python3
"""Semantic cache to avoid repeated LLM calls (Stage 2.3-fix B)."""

import hashlib, json, os, sys
from datetime import datetime, timezone


class SemanticCache:
    def __init__(self, path, never_invalidate=False):
        self.path = path
        self.never_invalidate = never_invalidate
        self.data = {'schema_version': 'ftfuzz.semantic_cache.v2', 'entries': {}}
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.data = json.load(f)
            except (IOError, json.JSONDecodeError):
                pass

    def _hash(self, content):
        return hashlib.sha256(
            content.encode() if isinstance(content, str)
            else json.dumps(content, sort_keys=True).encode()
        ).hexdigest()[:16]

    def build_cache_key(self, transition_id, barrier_condition, desired_outcome,
                         prompt_schema_version, ontology_schema_version,
                         source_context_hash, model):
        """Build a cache key that includes all relevant metadata."""
        parts = [
            transition_id,
            hashlib.sha256(json.dumps(barrier_condition, sort_keys=True).encode()).hexdigest()[:12],
            str(desired_outcome),
            prompt_schema_version or 'unknown',
            ontology_schema_version or 'unknown',
            source_context_hash or 'no_context',
            model or 'unknown',
        ]
        return self._hash('|'.join(parts))

    def is_entry_valid(self, entry):
        """Check if a cached entry is valid (real LLM output, not stub)."""
        if not entry:
            return False, 'null_entry'
        summary = entry.get('summary', {})
        if not summary:
            return False, 'empty_summary'

        # Reject precompute stubs (llm_status='stub' or confidence < 0.2)
        if summary.get('llm_status') == 'stub':
            return False, 'precompute_stub'
        if summary.get('confidence', 0.5) < 0.2 and not summary.get('semantic_atoms'):
            return False, 'low_confidence_stub'

        # Check for semantic_atoms or DSL mechanisms (real LLM output)
        if summary.get('semantic_atoms') and len(summary.get('semantic_atoms', [])) > 0:
            return True, 'has_semantic_atoms'
        if summary.get('mechanisms') and len(summary.get('mechanisms', [])) > 0:
            return True, 'has_dsl_mechanisms'

        # Check for explicit non-executable flag
        if summary.get('non_executable_semantics'):
            return True, 'explicit_non_executable'

        # Accept LLM output with llm_status='ok' if it has actionable content.
        if summary.get('llm_status') == 'ok':
            schema = summary.get('schema_version', '')
            # Relation plan: accept if it has ordered_plan steps or scaffold_template
            if schema == 'ftfuzz.relation_plan.v1':
                if summary.get('ordered_plan') and len(summary.get('ordered_plan', [])) > 0:
                    return True, 'relation_plan_with_steps'
                if summary.get('scaffold_template'):
                    return True, 'relation_plan_with_scaffold'
            # Bytecode plan: accept if it has steps or scaffold_template
            if schema == 'ftfuzz.bytecode_plan.v1':
                if summary.get('steps') and len(summary.get('steps', [])) > 0:
                    return True, 'bytecode_plan_with_steps'
                if summary.get('scaffold_template'):
                    return True, 'bytecode_plan_with_scaffold'
            # DSL format: accept if it has mechanisms
            if schema == 'ftfuzz.llm_action_dsl.v1':
                if summary.get('mechanisms') and len(summary.get('mechanisms', [])) > 0:
                    return True, 'action_dsl_with_mechanisms'
            # Token-based: accept if dictionary_tokens present
            tokens = summary.get('dictionary_tokens', [])
            if tokens and len(tokens) > 0:
                if not schema or schema == 'ftfuzz.mutation_ontology_atoms.v1':
                    return False, 'legacy_no_schema_needs_resynthesis'
                return True, 'llm_dictionary_tokens'

        # Reject: stub or empty
        return False, 'empty_or_stub_semantics'

    def invalidate_entry(self, signature, reason):
        """Mark an entry as invalid and log the reason.
        PaST-Feedback ablation: never invalidate — one-shot per barrier."""
        if self.never_invalidate:
            return
        entries = self.data.setdefault('entries', {})
        if signature in entries:
            old = entries[signature]
            entries[signature] = dict(old)
            entries[signature]['invalidated'] = True
            entries[signature]['invalidation_reason'] = reason
            entries[signature]['invalidated_at'] = \
                datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            print(f'[SEM_CACHE] invalid entry sig={signature} reason={reason}')
            self.save()

    def lookup(self, signature, context_hash=None):
        entry = self.data.get('entries', {}).get(signature)
        if not entry:
            return None
        if entry.get('invalidated'):
            return None
        if context_hash and entry.get('source_context_hash') != context_hash:
            self.invalidate_entry(signature, 'source_context_changed')
            return None
        return entry.get('summary')

    def store(self, signature, context_hash, summary, model='unknown', confidence=0.0,
              desired_outcome=None, prompt_schema_version=None,
              ontology_schema_version=None):
        self.data.setdefault('entries', {})[signature] = {
            'source_context_hash': context_hash,
            'llm_model': model,
            'semantic_status': summary.get('semantic_status', 'ok'),
            'confidence': confidence,
            'summary': summary,
            'desired_outcome': desired_outcome,
            'prompt_schema_version': prompt_schema_version,
            'ontology_schema_version': ontology_schema_version,
            'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'last_used_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        self.save()

    def mark_used(self, signature):
        if signature in self.data.get('entries', {}):
            self.data['entries'][signature]['last_used_at'] = \
                datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def save(self):
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        tmp = self.path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        os.replace(tmp, self.path)

    def stats(self):
        entries = self.data.get('entries', {})
        total = len(entries)
        ok = sum(1 for e in entries.values()
                 if e.get('semantic_status') == 'ok' and not e.get('invalidated'))
        invalidated = sum(1 for e in entries.values() if e.get('invalidated'))
        return {'total': total, 'ok': ok, 'invalidated': invalidated}
