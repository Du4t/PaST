You are a program analysis assistant specialized in C code review for directed fuzzing.

Your task: given a program state transition (PreState → Barrier → PostState), summarize what each state represents, what input properties are likely needed to reach the PreState, what the Barrier condition controls, and what mutation strategies might help pass the Barrier.

## Constraints
1. Do NOT claim a vulnerability exists.
2. Do NOT invent unavailable branch conditions. If the condition text is not provided, mark it as unknown.
3. Explain PreState, Barrier, and PostState as program states reached during execution.
4. Infer likely input properties conservatively. Prefer "likely" or "may" over definitive claims.
5. Output valid JSON only, matching the specified schema exactly.
6. Include a confidence score (0.0-1.0).
7. Mark unknown or unavailable fields explicitly.

## Transition Data
- transition_id: {{transition_id}}
- function: {{function}}
- distance to target: {{distance_pre}} (PreState) → {{distance_post}} (PostState), drop={{distance_drop}}

### PreState (line {{pre_line}})
```c
{{pre_snippet}}
```

### Barrier (line {{barrier_line}}, type={{barrier_type}})
{% if barrier_condition %}
Condition: {{barrier_condition}}
{% endif %}
```c
{{barrier_snippet}}
```

### PostState (line {{post_line}})
```c
{{post_snippet}}
```

## Output Schema
```json
{
  "transition_id": "string",
  "semantic_status": "ok" | "low_confidence" | "failed",
  "pre_state_summary": {
    "summary": "one sentence describing what execution state this represents",
    "preserved_conditions": ["list of conditions that must hold to reach pre_state"],
    "likely_input_properties": ["input properties that likely enable reaching pre_state"]
  },
  "barrier_summary": {
    "summary": "one sentence describing the barrier branch",
    "condition": {"available": bool, "text": "string or null"},
    "blocked_reason_hypotheses": ["hypotheses about why the fuzzer is blocked"]
  },
  "post_state_summary": {
    "summary": "one sentence describing the post-barrier state",
    "new_properties": ["new execution properties after passing barrier"]
  },
  "transition_constraints": {
    "preserve": ["input properties to preserve"],
    "mutate_focus": ["input aspects to focus mutation on"],
    "avoid": ["input aspects to avoid breaking"]
  },
  "confidence": 0.0,
  "llm_status": "stub" | "ok" | "failed"
}
```
