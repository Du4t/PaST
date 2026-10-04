import json
import os
import sys
import time
from typing import Dict, List, Optional

from .schemas import ResolverOutput
from policy.policy_store import write_policy, validate_policy


def compile_policy(barrier_report: Dict, field_hypotheses: List[Dict],
                   resolver_output: ResolverOutput) -> Dict:
    transition = barrier_report.get("transition_id", "T_UNKNOWN")
    barrier = barrier_report.get("barrier_id", "B_UNKNOWN")
    pre_state = barrier_report.get("pre_state_id", "S_PRE")
    post_state = barrier_report.get("post_state_id", "S_POST")

    preserve_ranges = []
    for pr in resolver_output.preserve_ranges:
        preserve_ranges.append({
            "start": pr.get("start", 0),
            "end": pr.get("end", 0),
            "weight": 0.95,
            "reason": pr.get("reason", "pre_preserving"),
        })

    focus_ranges = []
    for fr in resolver_output.focus_ranges:
        focus_ranges.append({
            "start": fr.get("start", 0),
            "end": fr.get("end", 0),
            "weight": 0.85,
            "role": fr.get("role", "transition_enabling"),
        })

    numeric_fields = []
    for sf in resolver_output.selected_fields:
        if sf.role == "transition_enabling" and sf.semantic_type in ("length", "count", "offset"):
            actions = sf.actions if sf.actions else ["boundary", "inc", "dec"]
            numeric_fields.append({
                "start": sf.range_start,
                "end": sf.range_end,
                "width": sf.width,
                "endian": sf.endian,
                "signed": sf.signed,
                "role": sf.semantic_type,
                "actions": actions,
                "confidence": sf.confidence,
            })

    dictionary_tokens = []
    for sf in resolver_output.selected_fields:
        if sf.semantic_type in ("magic", "type") and sf.preserve:
            token_hex = ""
            dictionary_tokens.append({
                "token_hex": token_hex or "00",
                "weight": 0.7,
                "reason": sf.semantic_type,
            })

    repair_rules = []
    for rs in resolver_output.repair_suggestions:
        rule = {"type": rs.get("type", "checksum_repair")}
        if "length_range" in rs:
            rule["length_range"] = rs["length_range"]
        if "payload_range" in rs:
            rule["payload_range"] = rs["payload_range"]
        rule["endian"] = rs.get("endian", "big")
        repair_rules.append(rule)

    num_numeric = len(numeric_fields)
    num_dict = len(dictionary_tokens)
    num_repair = len(repair_rules)

    total = 1.0
    numeric_w = 0.0
    dict_w = 0.0
    repair_w = 0.0
    fallback_w = 0.1

    if num_numeric > 0:
        numeric_w = 0.6
    if num_dict > 0:
        dict_w = 0.15
    if num_repair > 0:
        repair_w = 0.15

    remaining = total - fallback_w
    if num_numeric > 0 or num_dict > 0 or num_repair > 0:
        scale = remaining / (numeric_w + dict_w + repair_w + 0.001)
        numeric_w *= scale
        dict_w *= scale
        repair_w *= scale
    else:
        fallback_w = 1.0
        numeric_w = 0.0
        dict_w = 0.0
        repair_w = 0.0

    operator_weights = {
        "numeric_boundary": round(numeric_w * 0.5, 4),
        "directional_arithmetic": round(numeric_w * 0.5, 4),
        "byte_pattern_insert": round(dict_w, 4),
        "repair": round(repair_w, 4),
        "fallback": round(fallback_w, 4),
    }

    policy = {
        "policy_id": f"P_{transition}_{barrier}",
        "version": 1,
        "enabled": True,
        "target_transition": {
            "transition_id": transition,
            "pre_state_id": pre_state,
            "post_state_id": post_state,
            "barrier_id": barrier,
        },
        "activation": {
            "required_barrier_id": barrier,
            "min_pre_hits": barrier_report.get("min_pre_hits", 100),
            "max_stsr": barrier_report.get("max_stsr", 0.05),
            "seed_state": "reach_pre",
        },
        "preserve_ranges": preserve_ranges,
        "focus_ranges": focus_ranges,
        "numeric_fields": numeric_fields,
        "dictionary_tokens": dictionary_tokens,
        "operator_weights": operator_weights,
        "repair_rules": repair_rules,
        "validation": {
            "success_signal": "reach_post",
            "max_trials": 5000,
            "downgrade_on_no_gain": True,
        },
    }

    return policy


def compile_and_store(barrier_report: Dict, field_hypotheses: List[Dict],
                      resolver_output: ResolverOutput) -> Dict:
    policy = compile_policy(barrier_report, field_hypotheses, resolver_output)

    ok, err = validate_policy(policy)
    if not ok:
        policy["enabled"] = False
        policy["_validation_error"] = err

    write_policy(policy)
    return policy


if __name__ == "__main__":
    barrier_report = {
        "transition_id": "T_001",
        "barrier_id": "B_017",
        "pre_state_id": "S_MAGIC_OK",
        "post_state_id": "S_LEN_OK",
        "pre_hits": 12840,
        "post_hits": 21,
        "stsr": 0.0016,
    }

    from llm.schemas import ResolvedField
    resolver_output = ResolverOutput(
        transition_id="T_001",
        barrier_id="B_017",
        selected_fields=[
            ResolvedField(
                candidate_id="C1", range_start=0, range_end=4, width=4,
                endian="big", signed=False, role="pre_preserving",
                semantic_type="magic", actions=["preserve"],
                preserve=True, focus=False, confidence=0.9,
            ),
            ResolvedField(
                candidate_id="C2", range_start=4, range_end=8, width=4,
                endian="big", signed=False, role="transition_enabling",
                semantic_type="length", actions=["boundary", "inc", "dec", "fit_rhs"],
                preserve=False, focus=True, confidence=0.82,
            ),
        ],
        preserve_ranges=[{"start": 0, "end": 4, "reason": "magic"}],
        focus_ranges=[{"start": 4, "end": 8, "role": "length"}],
        repair_suggestions=[{"type": "length_recompute", "length_range": [4, 8], "endian": "big"}],
        overall_confidence=0.82,
    )

    policy = compile_policy(barrier_report, [], resolver_output)
    print(json.dumps(policy, indent=2))
