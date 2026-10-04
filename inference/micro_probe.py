import os
import json
import struct
import subprocess
import tempfile
from typing import List, Dict, Optional

from .schemas import FieldHypothesis, MicroProbeResult, CandidateRole


BOUNDARY_VALUES = [
    0, 1, -1, 15, 16, 31, 32, 63, 64, 65,
    127, 128, 255, 256, 1024, 4096,
    0x7fffffff, 0x80000000, 0xffffffff,
]

PERTURBATION_DELTAS = [-16, -4, -1, 1, 4, 16]


class MicroProbe:
    def __init__(self, target_bin: str, timeout: float = 5.0,
                 max_probes_per_field: int = 20, max_fields: int = 5):
        self.target_bin = target_bin
        self.timeout = timeout
        self.max_probes_per_field = max_probes_per_field
        self.max_fields = max_fields

    def apply_perturbation(self, seed_data: bytes, hypothesis: FieldHypothesis,
                           delta: int) -> bytes:
        modified = bytearray(seed_data)
        offset = hypothesis.range_start
        width = hypothesis.width
        endian = hypothesis.endian

        if offset + width > len(modified):
            return seed_data

        current = self._read_field(modified, offset, width, endian, hypothesis.signed)
        new_val = current + delta
        self._write_field(modified, offset, width, endian, new_val)
        return bytes(modified)

    def apply_boundary_value(self, seed_data: bytes, hypothesis: FieldHypothesis,
                             boundary_val: int) -> bytes:
        modified = bytearray(seed_data)
        offset = hypothesis.range_start
        width = hypothesis.width
        endian = hypothesis.endian

        if offset + width > len(modified):
            return seed_data

        self._write_field(modified, offset, width, endian, boundary_val)
        return bytes(modified)

    def _read_field(self, buf: bytearray, offset: int, width: int,
                    endian: str, signed: bool) -> int:
        fmt_map = {
            (1, "little", False): "<B", (1, "big", False): ">B",
            (1, "little", True): "<b", (1, "big", True): ">b",
            (2, "little", False): "<H", (2, "big", False): ">H",
            (2, "little", True): "<h", (2, "big", True): ">h",
            (4, "little", False): "<I", (4, "big", False): ">I",
            (4, "little", True): "<i", (4, "big", True): ">i",
            (8, "little", False): "<Q", (8, "big", False): ">Q",
            (8, "little", True): "<q", (8, "big", True): ">q",
        }
        fmt = fmt_map.get((width, endian, signed))
        if fmt is None:
            return 0
        chunk = bytes(buf[offset:offset + width])
        return struct.unpack(fmt, chunk)[0]

    def _write_field(self, buf: bytearray, offset: int, width: int,
                     endian: str, value: int) -> None:
        fmt_map = {
            (1, "little", False): "<B", (1, "big", False): ">B",
            (1, "little", True): "<b", (1, "big", True): ">b",
            (2, "little", False): "<H", (2, "big", False): ">H",
            (2, "little", True): "<h", (2, "big", True): ">h",
            (4, "little", False): "<I", (4, "big", False): ">I",
            (4, "little", True): "<i", (4, "big", True): ">i",
            (8, "little", False): "<Q", (8, "big", False): ">Q",
            (8, "little", True): "<q", (8, "big", True): ">q",
        }
        fmt = fmt_map.get((width, endian, False))
        if fmt is None:
            return
        try:
            packed = struct.pack(fmt, value & ((1 << (width * 8)) - 1))
            buf[offset:offset + width] = packed
        except struct.error:
            pass

    def run_target(self, input_data: bytes) -> Dict:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(input_data)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [self.target_bin, tmp_path],
                timeout=self.timeout,
                capture_output=True,
            )
            return {
                "returncode": result.returncode,
                "crash": result.returncode < 0,
                "timeout": False,
            }
        except subprocess.TimeoutExpired:
            return {"returncode": -1, "crash": False, "timeout": True}
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def probe_field(self, seed_data: bytes, hypothesis: FieldHypothesis,
                    cmp_rhs_values: Optional[List[int]] = None) -> List[MicroProbeResult]:
        results = []
        probe_count = 0

        for delta in PERTURBATION_DELTAS:
            if probe_count >= self.max_probes_per_field:
                break
            modified = self.apply_perturbation(seed_data, hypothesis, delta)
            exec_result = self.run_target(modified)
            results.append(MicroProbeResult(
                candidate_id=hypothesis.candidate_id,
                perturbation=delta,
                pre_state_preserved=exec_result["returncode"] >= 0,
                distance_change=0,
                post_state_reached=False,
                crash_detected=exec_result.get("crash", False),
            ))
            probe_count += 1

        if cmp_rhs_values:
            for rhs in cmp_rhs_values[:5]:
                if probe_count >= self.max_probes_per_field:
                    break
                modified = self.apply_boundary_value(seed_data, hypothesis, rhs)
                exec_result = self.run_target(modified)
                results.append(MicroProbeResult(
                    candidate_id=hypothesis.candidate_id,
                    perturbation=rhs,
                    pre_state_preserved=exec_result["returncode"] >= 0,
                    distance_change=0,
                    post_state_reached=False,
                    crash_detected=exec_result.get("crash", False),
                ))
                probe_count += 1

        for bv in BOUNDARY_VALUES[:3]:
            if probe_count >= self.max_probes_per_field:
                break
            bv_masked = bv & ((1 << (hypothesis.width * 8)) - 1)
            modified = self.apply_boundary_value(seed_data, hypothesis, bv_masked)
            exec_result = self.run_target(modified)
            results.append(MicroProbeResult(
                candidate_id=hypothesis.candidate_id,
                perturbation=bv_masked,
                pre_state_preserved=exec_result["returncode"] >= 0,
                distance_change=0,
                post_state_reached=False,
                crash_detected=exec_result.get("crash", False),
            ))
            probe_count += 1

        return results

    def validate_hypotheses(self, seed_data: bytes,
                            hypotheses: List[FieldHypothesis],
                            cmp_rhs_values: Optional[List[int]] = None) -> List[FieldHypothesis]:
        updated = []
        for h in hypotheses[:self.max_fields]:
            results = self.probe_field(seed_data, h, cmp_rhs_values)
            crash_count = sum(1 for r in results if r.crash_detected)
            pre_preserved = sum(1 for r in results if r.pre_state_preserved)

            probe_gain = 0.0
            if results:
                probe_gain = (1.0 - pre_preserved / len(results)) * 0.5
                if crash_count > 0:
                    probe_gain += 0.3

            h.evidence["micro_probe_gain"] = round(probe_gain, 4)
            h.confidence = h.confidence * 0.7 + probe_gain * 0.3

            if probe_gain < 0.05 and h.confidence > 0.3:
                h.confidence *= 0.5

            updated.append(h)

        return updated

    def export_results(self, results: List[MicroProbeResult], output_path: str):
        data = []
        for r in results:
            data.append({
                "candidate_id": r.candidate_id,
                "perturbation": r.perturbation,
                "pre_state_preserved": r.pre_state_preserved,
                "distance_change": r.distance_change,
                "post_state_reached": r.post_state_reached,
                "crash_detected": r.crash_detected,
            })
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
