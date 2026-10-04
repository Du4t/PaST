# FTFuzz Relation-Aware Planning — LLM Prompt (Stage 2.5)

**PREFERRED FORMAT: `ftfuzz.bytecode_plan.v1`**
Use this format for ALL targets. It uses 8 format-agnostic byte-level opcodes
(FIND, WRITE, INSERT, DELETE, SET_INT, INC_INT, SIZE_TO, PRESERVE) that work
across ELF, SQL, XML, JSON, PNG, JPEG, and all other formats.

Fall back to `ftfuzz.relation_plan.v1` ONLY if you absolutely need cross-region
declaration/instance binding semantics that cannot be expressed as byte sequences.

**CRITICAL FORMAT REQUIREMENT:**
You MUST output a JSON object with `"schema_version"` set to EITHER:
- `"ftfuzz.bytecode_plan.v1"` (PREFERRED — see bytecode_plan_prompt.md for the full spec)
- `"ftfuzz.relation_plan.v1"` (legacy — only for complex cross-region constraints)

For bytecode_plan.v1, the JSON MUST contain: `steps` (array of {op, params}), `mechanism`, `target_alignment`.
For relation_plan.v1, the JSON MUST contain: `state_goal`, `mechanism`, `missing_preconditions`, `semantic_relations`, `ordered_plan`, `target_alignment`.

DO NOT output `pre_state_summary`, `barrier_summary`, or `post_state_summary` — those are NOT part of the expected output.
If you cannot produce the required format, output valid JSON with an empty `steps`/`ordered_plan` and explain why in `unsupported_or_uncertain`.

### Bytecode Plan Quick Reference (PREFERRED for all targets)

8 format-agnostic opcodes operating on raw byte buffer:

| Opcode | Params | Description |
|--------|--------|-------------|
| FIND | pattern(hex), output(str), start(opt), occurrence(opt) | Search for hex byte sequence |
| WRITE | offset(ref), data(hex) | Overwrite bytes at offset |
| INSERT | offset(ref), data(hex) | Insert bytes, shift right |
| DELETE | offset(ref), length(int) | Remove byte range, shift left |
| SET_INT | offset(ref), width(1/2/4/8), endian(le/be), value(int) | Write integer |
| INC_INT | offset(ref), width(1/2/4/8), endian(le/be), delta(int) | Add to integer |
| SIZE_TO | field_offset(ref), width, endian, range_start(ref), range_end(ref/END) | Set int to byte-range length |
| PRESERVE | offset(ref), length(int) | Protect range from havoc |

Offset syntax: absolute int (4, 64), {ref} ({elf_hdr}), {ref}+N ({elf_hdr}+16), END

**IMPORTANT: All hex values MUST be concrete bytes, NOT placeholder descriptions.**
- ✓ `"data": "02"` (single byte 0x02)
- ✓ `"pattern": "4946204e4f5420455849535453"` ("IF NOT EXISTS" in ASCII hex)
- ✗ `"data": "64-bit value"` (placeholder — WILL FAIL)
- ✗ `"pattern": "<root"` (ASCII text — use hex: "3c726f6f74")

See `bytecode_plan_prompt.md` for full specification and cross-format examples.

---

You are a semantic fuzzing policy analyst. Your task is to produce a **relation-aware ordered plan** for crossing a program barrier. You must identify **missing preconditions** and establish **cross-region relations** before proposing mutation steps.

## Context Provided

1. **Active frontier transition** — the closest progress edge to target that the fuzzer has reached but cannot cross.
2. **Upstream k-hop PostState context** — what program state objects were created/modified before reaching this barrier.
3. **Prior failed action history** (if any) — what was tried and why it failed.
4. **Global target context** — the final target function/state. Used as secondary alignment constraint only (primary objective is still the active frontier desired_outcome).

## Target Context (Global Planning Constraint)

```
{target_context}
```

IMPORTANT: Your plan must include a `target_alignment` section that explains:
- How each step relates to the final target function/state
- Which target-relevant objects your plan affects
- Any risks of over-repair (mutations that make parsing succeed but bypass the target)
- Actions to avoid (mutations that would prevent target reachability)

## Hard Target Constraints — MUST Follow

IF the target context above contains `target_avoid_overrepair_hints` or `target_relevant_conditions`, you MUST:

1. **Read every "avoid" hint as a HARD PROHIBITION.** If a hint says "Inputs with X will bypass the target", you MUST NOT generate a plan that produces X.
2. **Read every "condition" as a REQUIRED TRIGGER.** If a condition says "input MUST contain Y", your scaffold_template and dictionary_tokens MUST produce Y.
3. **Check your plan against EVERY avoid hint before finalizing.** If your plan matches any avoid hint, DISCARD it and try a different approach.
4. **If no allowed mechanism fits, prefer `unsupported` over a plan known to bypass the target.**

EXAMPLES of common mismatches:
- Target is inside a switch/conditional → specify which branch value triggers it
- Target requires specific input structure → do NOT use over-simplified scaffold
- Target requires cross-region consistency → do NOT mutate one side without the other

## Retry Guidance (if {failed_actions} indicates a retry)

If this context shows a previous failed plan:
1. **IDENTIFY what the previous plan did wrong** — was it too simple? Wrong mechanism? Wrong tokens?
2. **GENERATE a DIFFERENT approach** — try a different mechanism type, different tokens, different scaffold structure
3. **EXPLAIN in `target_alignment` why the new plan avoids the previous failure**

## Critical Rules

1. **Do NOT output a single-step action if missing preconditions exist.** You must identify what must be established first.
2. **Distinguish satisfied, missing, and uncertain dependencies.** Use `missing_preconditions` explicitly.
3. **Instance-side mutation alone is insufficient for typed/internal table barriers.** Identify the declaration/reference side.
4. **For `declaration_instance_binding`**: step 1 = ensure declaration, step 2 = insert matching instance.
5. **Do NOT output raw mutator op names.** Use only effects from the allowed enum.
6. **Preserve `desired_outcome` from input.** Do not decide branch direction.
7. **If the mechanism is unsupported, mark it `unsupported` and explain.**

## Allowed Relation Types

- `declaration_instance_binding` — Declaration side (DTD/schema) + instance side (element attribute)
- `reference_definition_binding` — Reference (IDREF) + definition (ID)
- `typed_field_materialization` — Typed field exists in both schema and instance
- `state_table_materialization` — Internal program table populated by typed fields
- `container_membership` — Instance belongs to declared container
- `unsupported`

## Allowed Ordered Effects

- `ensure_declaration_side` — Make sure the declaration region exists
- `ensure_typed_field_declaration` — Insert a typed field declaration (e.g., `<!ATTLIST elem attr TYPE #IMPLIED>`)
- `insert_matching_instance_field` — Insert a matching instance-side field
- `preserve_binding_keys` — Keep binding keys (element name, attribute name) consistent
- `preserve_reachability_region` — Protect structural tokens
- `unsupported`

## Output Format

You MUST output valid JSON. The `state_goal` describes what program state change is needed. The `mechanism` describes the high-level strategy. `ordered_plan` lists mutation steps in order. `dictionary_tokens` are byte-level tokens for the mutator. `scaffold_template` is a complete valid input example.

**CRITICAL — Byte-Level Field Identification:** You MUST identify specific byte ranges that control the barrier and output them in `focus_ranges`, `preserve_ranges`, `numeric_fields`, and `repair_rules`. These fields are REQUIRED, not optional:
- `focus_ranges`: byte ranges whose modification is likely to change the barrier outcome. If the barrier checks a single character, identify it: `[{"start": 0, "end": 1, "role": "first_char", "confidence": 0.98}]`. For multi-byte checks (length, offset, magic), include `width`, `endian`.
- `preserve_ranges`: byte ranges that must NOT be mutated to keep the input valid (e.g., SQL keywords, magic headers)
- `numeric_fields`: typed numeric fields with specific widths, endianness, and actions (inc, dec, boundary, fit_rhs)
- `repair_rules`: consistency rules (e.g., recompute length field after payload mutation)

**Even for simple single-byte barriers — if you identified which byte matters, you MUST put it in `focus_ranges`. Leaving these arrays empty when you HAVE identified byte ranges will cause the mutation system to fail.**

```json
{
  "schema_version": "ftfuzz.relation_plan.v1",
  "transition_id": "{transition_id}",
  "desired_outcome": true,
  "state_goal": {
    "target": "describe the program variable or state to influence",
    "desired_state": "what value or condition is needed",
    "confidence": 0.82
  },
  "mechanism": {
    "type": "choose from Allowed Relation Types below — use unsupported only as last resort",
    "summary": "Explain HOW your plan achieves the state_goal. Be specific about which input bytes affect which program state."
  },
  "missing_preconditions": [
    {
      "name": "what must exist before mutation",
      "currently_satisfied": false,
      "evidence": "why you believe this is missing",
      "required_before": "which step needs this precondition"
    }
  ],
  "semantic_relations": [
    {
      "relation_id": "R1",
      "type": "choose from Allowed Relation Types",
      "binding_keys": ["key fields that link regions"],
      "declaration_side": {
        "region_role": "where the structure/schema is defined",
        "effect": "what to do on this side",
        "parameters": {}
      },
      "instance_side": {
        "region_role": "where the value/instance appears",
        "effect": "what to do on this side",
        "parameters": {"value_policy": "fresh_unique or matching"}
      }
    }
  ],
  "ordered_plan": [
    {"step": 1, "effect": "first_mutation_effect", "target_region": "where", "parameters": {}},
    {"step": 2, "effect": "second_mutation_effect", "target_region": "where", "parameters": {}}
  ],
  "success_oracle": ["desired_edge_taken", "min_distance_decreases"],
  "unsupported_or_uncertain": [],
  "dictionary_tokens": ["CONCRETE hex byte sequences to insert. NO placeholders like {VERSION} or {LENGTH} — use actual byte values like FF4F or 0x02 0x00. The LAST token is the insertion anchor marker."],
  "precondition_tokens": ["CONCRETE hex byte sequences that MUST already exist in the seed. NO placeholders like {VERSION} or {LENGTH}. Each token must be an actual byte pattern found at the intended mutation site (e.g., the bytes immediately before where you want to insert). The LAST precondition token is used as the insertion anchor point — it must be UNIQUE to the target region."],
  "scaffold_template": "Complete valid input as CONCRETE hex-encoded bytes. MUST be actual byte values — NOT a human-readable description, NOT placeholder text. For binary formats, use hex bytes like 7F454C46... or 0x7F 0x45 0x4C 0x46. For text formats, use the actual text content.",
  "scaffold_script": "Optional. Python3 script that outputs the complete valid input to stdout as raw binary bytes. Use this INSTEAD of scaffold_template for binary formats (ELF, DWARF, etc.) where hand-computing hex bytes is error-prone. The script can use any Python standard library including open(). Output binary via sys.stdout.buffer.write().",
  "focus_ranges": [
    {"start": 4, "end": 8, "role": "length", "width": 4, "endian": "big", "confidence": 0.85}
  ],
  "preserve_ranges": [
    {"start": 0, "end": 4, "role": "magic", "confidence": 0.95}
  ],
  "numeric_fields": [
    {"start": 4, "end": 8, "width": 4, "endian": "big", "signed": false, "role": "length", "actions": ["boundary", "inc", "dec", "fit_rhs"], "confidence": 0.85}
  ],
  "repair_rules": [
    {"type": "length_recompute", "length_range": [4, 8], "endian": "big"}
  ],
  "target_alignment": {
    "target_function": "string",
    "overrepair_risks": ["risks where mutations satisfy parsing but bypass the target"],
    "avoid_actions": ["specific actions or mutation patterns to avoid"]
  }
}
```

## Seed Data (Example Inputs)

Below are example seeds that reach the barrier. Use their hex/text content to identify which byte ranges control the barrier condition. Compare multiple seeds to see which bytes are constant (preserve) vs. which vary (focus).

{seed_data}

## Transition Data

```
Active Transition: {transition_id}
Desired Outcome: {desired_outcome}
Function: {active_function}:{active_source}
Barrier Condition: {barrier_condition}
PreState Summary: {pre_state_summary}
PostState Summary: {post_state_summary}
State Goal Hint: {state_goal_hint}

Upstream PostState Context (k={upstream_hops}):
{upstream_context}

Prior Failed Actions:
{failed_actions}
```

Produce the relation plan JSON.
