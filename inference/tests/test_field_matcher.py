import os
import sys
import json
import struct
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from inference.field_matcher import FieldMatcher, decode_field, compute_pre_preserve, compute_transition_gain


def test_decode_field():
    buf = b'\x00\x00\x00\x04\x41\x41\x41\x41'
    val = decode_field(buf, 0, 4, "big", False)
    assert val == 4, f"Expected 4, got {val}"

    val = decode_field(buf, 4, 4, "big", False)
    assert val == 0x41414141, f"Expected 0x41414141, got {val}"

    print("[PASS] decode_field")


def test_compute_pre_preserve():
    values = [4, 4, 4, 4, 4]
    rate = compute_pre_preserve(values, [8])
    assert rate == 1.0, f"Expected 1.0, got {rate}"

    values = [4, 8, 4, 8, 4]
    rate = compute_pre_preserve(values, [8])
    assert rate == 0.6, f"Expected 0.6, got {rate}"

    print("[PASS] compute_pre_preserve")


def test_compute_transition_gain():
    pre = [4, 4, 4]
    post = [8, 12, 16]
    gain = compute_transition_gain(pre, post)
    assert gain == 1.0, f"Expected 1.0, got {gain}"

    pre = [4, 4, 4]
    post = [4, 4, 4]
    gain = compute_transition_gain(pre, post)
    assert gain == 0.0, f"Expected 0.0, got {gain}"

    print("[PASS] compute_transition_gain")


def test_field_matcher_with_seeds():
    tmpdir = tempfile.mkdtemp()

    pre_seeds = []
    for i in range(5):
        path = os.path.join(tmpdir, f"pre_{i}")
        data = b'\xDE\xAD\xBE\xEF' + struct.pack('>I', 4 + i) + b'\x00' * 20
        with open(path, 'wb') as f:
            f.write(data)
        pre_seeds.append(path)

    post_seeds = []
    for i in range(3):
        path = os.path.join(tmpdir, f"post_{i}")
        data = b'\xDE\xAD\xBE\xEF' + struct.pack('>I', 20 + i * 4) + b'\x00' * 20
        with open(path, 'wb') as f:
            f.write(data)
        post_seeds.append(path)

    matcher = FieldMatcher("T_001", "B_017")
    matcher.load_seeds("reach_pre", pre_seeds)
    matcher.load_seeds("near_post", post_seeds)

    hypotheses = matcher.infer_fields(widths=(4,), max_offset=16)

    assert len(hypotheses) > 0, "Expected at least one hypothesis"

    length_candidates = [h for h in hypotheses if h.range_start == 4 and h.width == 4]
    assert len(length_candidates) > 0, "Expected length field candidate at offset 4"

    print(f"[PASS] field_matcher: found {len(hypotheses)} hypotheses")
    for h in hypotheses[:5]:
        print(f"  {h.candidate_id}: [{h.range_start},{h.range_end}) w={h.width} "
              f"role={h.candidate_role.value} conf={h.confidence:.3f}")


if __name__ == "__main__":
    test_decode_field()
    test_compute_pre_preserve()
    test_compute_transition_gain()
    test_field_matcher_with_seeds()
    print("\nAll field_matcher tests passed!")
