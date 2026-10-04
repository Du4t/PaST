import json
import os
import sys
from typing import Dict, List, Optional

from .schemas import ResolverOutput, ResolvedField


PROMPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")


def load_prompt(filename: str) -> str:
    path = os.path.join(PROMPTS_DIR, filename)
    with open(path, "r") as f:
        return f.read()


def render_user_prompt(barrier_report: Dict, field_hypotheses: List[Dict],
                       source_context: str = "", micro_probe_results: List[Dict] = None) -> str:
    template = load_prompt("semantic_resolver_user_template.txt")
    return template.format(
        barrier_report=json.dumps(barrier_report, indent=2),
        field_hypotheses=json.dumps(field_hypotheses, indent=2),
        source_context=source_context or "(not available)",
        micro_probe_results=json.dumps(micro_probe_results or [], indent=2),
    )


def validate_resolver_output(data: Dict) -> bool:
    required_keys = ["transition_id", "barrier_id", "selected_fields"]
    for key in required_keys:
        if key not in data:
            return False
    for field in data.get("selected_fields", []):
        if "candidate_id" not in field:
            return False
        if "role" not in field:
            return False
    return True


def parse_resolver_output(json_str: str) -> Optional[ResolverOutput]:
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return None

    if not validate_resolver_output(data):
        return None

    selected_fields = []
    for fd in data.get("selected_fields", []):
        selected_fields.append(ResolvedField(
            candidate_id=fd.get("candidate_id", ""),
            range_start=fd.get("range_start", 0),
            range_end=fd.get("range_end", 0),
            width=fd.get("width", 4),
            endian=fd.get("endian", "big"),
            signed=fd.get("signed", False),
            role=fd.get("role", "unknown"),
            semantic_type=fd.get("semantic_type", "unknown"),
            actions=fd.get("actions", []),
            preserve=fd.get("preserve", False),
            focus=fd.get("focus", False),
            confidence=fd.get("confidence", 0.0),
            rationale=fd.get("rationale", ""),
        ))

    return ResolverOutput(
        transition_id=data.get("transition_id", ""),
        barrier_id=data.get("barrier_id", ""),
        selected_fields=selected_fields,
        preserve_ranges=data.get("preserve_ranges", []),
        focus_ranges=data.get("focus_ranges", []),
        dictionary_tokens=data.get("dictionary_tokens", []),
        repair_suggestions=data.get("repair_suggestions", []),
        overall_confidence=data.get("overall_confidence", 0.0),
        rationale_summary=data.get("rationale_summary", ""),
    )


def call_llm(system_prompt: str, user_prompt: str, model: str = None,
             api_url: str = None, api_key: str = None) -> str:
    model = model or os.environ.get("FTFUZZ_LLM_MODEL", "gpt-3.5-turbo")
    api_url = api_url or os.environ.get("FTFUZZ_LLM_API_URL", "https://api.openai.com/v1/chat/completions")
    api_key = api_key or os.environ.get("FTFUZZ_LLM_API_KEY", "")

    if not api_key:
        raise RuntimeError("No LLM API key provided. Set FTFUZZ_LLM_API_KEY or use no-LLM mode.")

    try:
        import urllib.request
        payload = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 2048,
        }).encode("utf-8")

        req = urllib.request.Request(
            api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        raise RuntimeError(f"LLM API call failed: {e}")


def rule_based_resolve(barrier_report: Dict, field_hypotheses: List[Dict],
                       source_context: str = "") -> ResolverOutput:
    transition_id = barrier_report.get("transition_id", "T_UNKNOWN")
    barrier_id = barrier_report.get("barrier_id", "B_UNKNOWN")

    selected = []
    preserve_ranges = []
    focus_ranges = []
    repair_suggestions = []
    dict_tokens = []

    for fh in sorted(field_hypotheses, key=lambda x: x.get("confidence", 0), reverse=True):
        role = fh.get("candidate_role", "unknown")
        sem_type = fh.get("semantic_type", "unknown")
        start = fh.get("range", [0, 0])[0]
        end = fh.get("range", [0, 0])[1]
        width = fh.get("width", 4)
        endian = fh.get("endian", "big")
        signed = fh.get("signed", False)

        if role == "pre_preserving":
            preserve_ranges.append({"start": start, "end": end, "reason": sem_type})
            selected.append(ResolvedField(
                candidate_id=fh.get("candidate_id", ""),
                range_start=start, range_end=end, width=width,
                endian=endian, signed=signed,
                role="pre_preserving", semantic_type=sem_type,
                actions=["preserve"], preserve=True, focus=False,
                confidence=fh.get("confidence", 0.5),
                rationale=f"PreState-preserving {sem_type} field",
            ))
        elif role == "transition_enabling":
            focus_ranges.append({"start": start, "end": end, "role": sem_type})
            actions = ["boundary", "inc", "dec"]
            if sem_type == "length":
                actions.append("fit_rhs")
                repair_suggestions.append({
                    "type": "length_recompute",
                    "length_range": [start, end],
                    "endian": endian,
                })
            selected.append(ResolvedField(
                candidate_id=fh.get("candidate_id", ""),
                range_start=start, range_end=end, width=width,
                endian=endian, signed=signed,
                role="transition_enabling", semantic_type=sem_type,
                actions=actions, preserve=False, focus=True,
                confidence=fh.get("confidence", 0.5),
                rationale=f"Transition-enabling {sem_type} field",
            ))
        elif role == "post_stabilizing":
            repair_suggestions.append({
                "type": "payload_size_fit",
                "length_range": [start, end],
                "endian": endian,
            })
            selected.append(ResolvedField(
                candidate_id=fh.get("candidate_id", ""),
                range_start=start, range_end=end, width=width,
                endian=endian, signed=signed,
                role="post_stabilizing", semantic_type=sem_type,
                actions=["boundary"], preserve=False, focus=False,
                confidence=fh.get("confidence", 0.5),
                rationale=f"PostState-stabilizing {sem_type} field",
            ))

    overall_conf = 0.0
    if field_hypotheses:
        overall_conf = max(h.get("confidence", 0) for h in field_hypotheses)

    return ResolverOutput(
        transition_id=transition_id,
        barrier_id=barrier_id,
        selected_fields=selected,
        preserve_ranges=preserve_ranges,
        focus_ranges=focus_ranges,
        dictionary_tokens=dict_tokens,
        repair_suggestions=repair_suggestions,
        overall_confidence=overall_conf,
        rationale_summary=f"Rule-based resolution for {transition_id}/{barrier_id}",
    )


class SemanticResolver:
    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self.system_prompt = load_prompt("semantic_resolver_system.txt")

    def resolve(self, barrier_report: Dict, field_hypotheses: List[Dict],
                source_context: str = "", micro_probe_results: List[Dict] = None) -> ResolverOutput:
        if not self.use_llm:
            return rule_based_resolve(barrier_report, field_hypotheses, source_context)

        user_prompt = render_user_prompt(barrier_report, field_hypotheses,
                                         source_context, micro_probe_results)

        try:
            response = call_llm(self.system_prompt, user_prompt)
            output = parse_resolver_output(response)
            if output is not None:
                return output
        except Exception:
            pass

        return rule_based_resolve(barrier_report, field_hypotheses, source_context)
