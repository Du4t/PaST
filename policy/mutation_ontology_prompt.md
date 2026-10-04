# FTFuzz Action DSL — LLM Prompt Template (Stage: Action DSL)

You are a semantic fuzzing policy analyst. Your task is to produce an **executable Action DSL plan** for crossing a program barrier. You must output atomic, verifiable actions with explicit failure handling.

**You are NOT producing:**
- Raw token insertions (e.g., `INSERT_TOKEN_IN_REGION(xml:id=)`)
- Free-text mutation advice
- Incomplete attribute/field fragments

**You MUST produce:**
- Complete Action DSL with primary_path and fallback_construction_path
- Full attribute/field literals with value generation
- Explicit forbidden_actions declaring what NOT to do

---

## Allowed Opcodes

### Slot Discovery
`FIND_START_TAG_ATTR_SLOT` — Find an attribute-insertion position inside a start tag
`FIND_CONTAINER_INSERT_SLOT` — Find a position inside a container for element insertion

### Checks
`CHECK_SLOT_NOT_IN_CLOSING_TAG` / `CHECK_SLOT_NOT_IN_COMMENT` / `CHECK_SLOT_NOT_IN_CDATA`
`CHECK_ATTR_ABSENT_IN_TAG` — Verify attribute not already present

### Value / Name Generation
`GEN_IDENTIFIER_VALUE` — Generate unique ID value (e.g., ftid_001)
`GEN_FRESH_NAME` — Generate unique element name (e.g., ftnode_001)

### Mutation / Construction
`INSERT_ATTRIBUTE` — Insert complete attribute `name="value"` at a slot
`INSERT_ELEMENT_PAIR_WITH_FIELD` — Create `<elem field="value"></elem>` pair

### Control Flow
`ON_FAIL_GOTO`, `ABORT_ACTION`, `DONE`

### Legacy (allowed only for non-structured barriers)
`PRESERVE_REGION`, `DELETE_REGION`, `EMPTY_REGION`, `REMOVE_TOKENS`, `FORBID_TOKENS`, `FOCUS_RANGE_HAVOC`

---

## Critical Rules

1. **For internal_table barriers** (e.g., `cur->ids != NULL`), you MUST NOT use `INSERT_TOKEN_IN_REGION`, `REMOVE_TOKENS`, or `FORBID_TOKENS`.
2. Every mechanism MUST have `primary_path` AND `fallback_construction_path`.
3. `INSERT_ATTRIBUTE` MUST include complete `literal_format` with `{value}` placeholder: e.g., ` xml:id="{value}"`.
4. `INSERT_ELEMENT_PAIR_WITH_FIELD` MUST include `literal_format` with `{element}` and `{value}`: e.g., `<{element} xml:id="{value}"></{element}>`.
5. `GEN_IDENTIFIER_VALUE` MUST specify a prefix (e.g., "ftid") and `unique_within_seed: true`.
6. Every action step MUST have `on_fail` or `on_success`.
7. You MUST output `forbidden_actions` explicitly declaring that raw token insertion (e.g., `xml:id=`) is prohibited.
8. If you cannot produce an executable plan, mark `executable: false` and explain why.
9. The Compiler will NOT add semantics — it only validates your plan.

---

## Output Format

```json
{
  "schema_version": "ftfuzz.llm_action_dsl.v1",
  "transition_id": "{transition_id}",
  "barrier_condition": "{barrier_condition}",
  "state_goal": {
    "kind": "materialize_internal_table",
    "object": "xmlDoc",
    "field": "ids",
    "desired": "non_null",
    "input_effect": "register_at_least_one_document_id"
  },
  "mechanisms": [
    {
      "mechanism_id": "M1",
      "name": "insert_complete_id_attribute",
      "confidence": 0.6,
      "primary_path": [
        {
          "op": "FIND_START_TAG_ATTR_SLOT",
          "output": "slot1",
          "params": {
            "prefer_ranges": ["focus_ranges", "non_preserve_ranges"],
            "allow_self_closing_tag": true
          },
          "on_fail": "goto_create_slot"
        },
        {
          "op": "CHECK_ATTR_ABSENT_IN_TAG",
          "slot_ref": "slot1",
          "params": { "attr_name": "xml:id" },
          "on_fail": "goto_create_slot"
        },
        {
          "op": "GEN_IDENTIFIER_VALUE",
          "output": "id1",
          "params": { "prefix": "ftid", "unique_within_seed": true },
          "on_fail": "goto_create_slot"
        },
        {
          "op": "INSERT_ATTRIBUTE",
          "slot_ref": "slot1",
          "params": {
            "attr_name": "xml:id",
            "attr_value_ref": "id1",
            "literal_format": " xml:id=\"{value}\""
          },
          "on_success": "DONE",
          "on_fail": "goto_create_slot"
        }
      ],
      "fallback_construction_path": [
        {
          "op": "FIND_CONTAINER_INSERT_SLOT",
          "output": "container_slot",
          "params": { "prefer_before_tail": true, "avoid_preserve_ranges": true },
          "on_fail": "ABORT_ACTION"
        },
        {
          "op": "GEN_FRESH_NAME",
          "output": "elem_name",
          "params": { "prefix": "ftnode" },
          "on_fail": "ABORT_ACTION"
        },
        {
          "op": "GEN_IDENTIFIER_VALUE",
          "output": "id2",
          "params": { "prefix": "ftid", "unique_within_seed": true },
          "on_fail": "ABORT_ACTION"
        },
        {
          "op": "INSERT_ELEMENT_PAIR_WITH_FIELD",
          "slot_ref": "container_slot",
          "params": {
            "element_name_ref": "elem_name",
            "field_name": "xml:id",
            "field_value_ref": "id2",
            "literal_format": "<{element} xml:id=\"{value}\"></{element}>"
          },
          "on_success": "DONE",
          "on_fail": "ABORT_ACTION"
        }
      ],
      "forbidden_actions": [
        {
          "op": "INSERT_TOKEN_IN_REGION",
          "token": "xml:id=",
          "reason": "incomplete attribute; lacks quoted value and structural insertion slot"
        }
      ]
    }
  ],
  "forbidden_actions": [
    {
      "op": "INSERT_TOKEN_IN_REGION",
      "token": "xml:id=",
      "reason": "unsafe for internal table materialization; must use structured INSERT_ATTRIBUTE or fallback construction"
    }
  ],
  "assumptions": ["Seed contains at least one XML element with parseable start tag"],
  "validation_metrics": {
    "expected_attribute_insertions": ">=1",
    "expected_fallback_creations": ">=1 if no start-tag slot found"
  }
}
```

---

## Transition Data

```
Transition ID: {transition_id}
Desired Branch Outcome: {desired_outcome}

PreState:  {pre_function}:{pre_source}
Barrier:   {barrier_function}:{barrier_source}
  Condition: {barrier_condition}
  Type: {barrier_type}
  True: dist={distance_true}  False: dist={distance_false}
PostState: {post_function}:{post_source}

Barrier source snippet:
{barrier_summary}
```

Produce the Action DSL plan.
