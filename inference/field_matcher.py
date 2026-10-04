import os
import struct
import json
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

from .schemas import FieldHypothesis, CandidateRole, SemanticType


def load_seed_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def decode_field(buf: bytes, offset: int, width: int, endian: str, signed: bool) -> Optional[int]:
    if offset + width > len(buf):
        return None
    chunk = buf[offset:offset + width]
    fmt_map = {
        (1, "little", False): "<B",
        (1, "big", False): ">B",
        (1, "little", True): "<b",
        (1, "big", True): ">b",
        (2, "little", False): "<H",
        (2, "big", False): ">H",
        (2, "little", True): "<h",
        (2, "big", True): ">h",
        (4, "little", False): "<I",
        (4, "big", False): ">I",
        (4, "little", True): "<i",
        (4, "big", True): ">i",
        (8, "little", False): "<Q",
        (8, "big", False): ">Q",
        (8, "little", True): "<q",
        (8, "big", True): ">q",
    }
    fmt = fmt_map.get((width, endian, signed))
    if fmt is None:
        return None
    return struct.unpack(fmt, chunk)[0]


def slide_windows(buf: bytes, widths=(1, 2, 4, 8), endians=("big", "little"),
                  signed_options=(False, True)):
    results = []
    for width in widths:
        for offset in range(0, len(buf) - width + 1):
            for endian in endians:
                for signed in signed_options:
                    val = decode_field(buf, offset, width, endian, signed)
                    if val is not None:
                        results.append({
                            "offset": offset,
                            "width": width,
                            "endian": endian,
                            "signed": signed,
                            "value": val,
                        })
    return results


def compute_match_rate(values_by_group: Dict[str, List[int]], target_value: int) -> float:
    total = 0
    matching = 0
    for group, vals in values_by_group.items():
        for v in vals:
            total += 1
            if v == target_value:
                matching += 1
    return matching / total if total > 0 else 0.0


def compute_correlation(values: List[int], targets: List[int]) -> float:
    if len(values) < 3 or len(values) != len(targets):
        return 0.0
    n = len(values)
    mean_v = sum(values) / n
    mean_t = sum(targets) / n
    cov = sum((v - mean_v) * (t - mean_t) for v, t in zip(values, targets))
    var_v = sum((v - mean_v) ** 2 for v in values)
    var_t = sum((t - mean_t) ** 2 for t in targets)
    if var_v == 0 or var_t == 0:
        return 0.0
    return cov / ((var_v * var_t) ** 0.5)


def compute_pre_preserve(values_pre: List[int], values_other: List[int]) -> float:
    if not values_pre:
        return 0.0
    mode = max(set(values_pre), key=values_pre.count)
    preserve_rate = values_pre.count(mode) / len(values_pre)
    return preserve_rate


def compute_transition_gain(values_pre: List[int], values_post: List[int]) -> float:
    if not values_pre or not values_post:
        return 0.0
    pre_set = set(values_pre)
    post_set = set(values_post)
    new_in_post = post_set - pre_set
    return len(new_in_post) / max(len(post_set), 1)


def compute_post_stability(values_post: List[int]) -> float:
    if not values_post:
        return 0.0
    mode = max(set(values_post), key=values_post.count)
    return values_post.count(mode) / len(values_post)


class FieldMatcher:
    def __init__(self, transition_id: str, barrier_id: str):
        self.transition_id = transition_id
        self.barrier_id = barrier_id
        self.seed_data = {"fail_pre": [], "reach_pre": [], "near_post": [], "reach_post": []}
        self.snapshot_vars = {}

    def load_seeds(self, group: str, seed_paths: List[str]):
        self.seed_data[group] = [load_seed_bytes(p) for p in seed_paths]

    def load_snapshots(self, snapshot_records: List[Dict]):
        for rec in snapshot_records:
            barrier_id = rec.get("barrier_id")
            var_id = rec.get("variable_id")
            value = rec.get("value")
            if barrier_id not in self.snapshot_vars:
                self.snapshot_vars[barrier_id] = {}
            if var_id not in self.snapshot_vars[barrier_id]:
                self.snapshot_vars[barrier_id][var_id] = []
            self.snapshot_vars[barrier_id][var_id].append(value)

    def infer_fields(self, widths=(1, 2, 4, 8), max_offset=256) -> List[FieldHypothesis]:
        hypotheses = []
        candidate_id = 0

        reach_pre = self.seed_data.get("reach_pre", [])
        reach_post = self.seed_data.get("reach_post", [])
        near_post = self.seed_data.get("near_post", [])

        if not reach_pre:
            return hypotheses

        ref_seed = reach_pre[0]
        max_off = min(max_offset, len(ref_seed))

        for width in widths:
            for offset in range(0, max_off - width + 1):
                for endian in ("big", "little"):
                    for signed in (False, True):
                        pre_values = []
                        for seed in reach_pre:
                            v = decode_field(seed, offset, width, endian, signed)
                            if v is not None:
                                pre_values.append(v)

                        post_values = []
                        for seed in reach_post + near_post:
                            v = decode_field(seed, offset, width, endian, signed)
                            if v is not None:
                                post_values.append(v)

                        if not pre_values:
                            continue

                        pre_preserve = compute_pre_preserve(pre_values, post_values)
                        transition_gain = compute_transition_gain(pre_values, post_values)
                        post_stability = compute_post_stability(post_values)

                        var_match = 0.0
                        if self.barrier_id in self.snapshot_vars:
                            for var_id, var_values in self.snapshot_vars[self.barrier_id].items():
                                if pre_values and var_values:
                                    min_len = min(len(pre_values), len(var_values))
                                    var_match = max(var_match,
                                                    compute_correlation(
                                                        pre_values[:min_len],
                                                        var_values[:min_len]))

                        score = (0.2 * pre_preserve +
                                 0.3 * transition_gain +
                                 0.2 * post_stability +
                                 0.3 * var_match)

                        if score < 0.1:
                            continue

                        if transition_gain > 0.5:
                            role = CandidateRole.TRANSITION_ENABLING
                        elif pre_preserve > 0.8:
                            role = CandidateRole.PRE_PRESERVING
                        elif post_stability > 0.8:
                            role = CandidateRole.POST_STABILIZING
                        else:
                            role = CandidateRole.UNKNOWN

                        semantic = SemanticType.UNKNOWN
                        if role == CandidateRole.TRANSITION_ENABLING:
                            if width in (2, 4) and pre_values:
                                avg = sum(pre_values) / len(pre_values)
                                if 1 < avg < 65536:
                                    semantic = SemanticType.LENGTH
                        elif role == CandidateRole.PRE_PRESERVING:
                            if width == 4 and pre_values:
                                semantic = SemanticType.MAGIC

                        candidate_id += 1
                        hypotheses.append(FieldHypothesis(
                            candidate_id=f"C{candidate_id}",
                            range_start=offset,
                            range_end=offset + width,
                            width=width,
                            endian=endian,
                            signed=signed,
                            candidate_role=role,
                            semantic_type=semantic,
                            confidence=round(score, 4),
                            evidence={
                                "var_match": round(var_match, 4),
                                "transition_gain": round(transition_gain, 4),
                                "pre_preserve": round(pre_preserve, 4),
                                "post_stability": round(post_stability, 4),
                            },
                        ))

        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses[:20]

    def export_hypotheses(self, hypotheses: List[FieldHypothesis], output_path: str):
        data = []
        for h in hypotheses:
            data.append({
                "candidate_id": h.candidate_id,
                "range": [h.range_start, h.range_end],
                "width": h.width,
                "endian": h.endian,
                "signed": h.signed,
                "candidate_role": h.candidate_role.value,
                "semantic_type": h.semantic_type.value,
                "confidence": h.confidence,
                "evidence": h.evidence,
            })
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
