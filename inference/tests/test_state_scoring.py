import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from inference.schemas import FieldHypothesis, CandidateRole, SemanticType
from inference.state_conditioned_scoring import score_field, rank_hypotheses, classify_role


def test_score_field():
    h = FieldHypothesis(
        candidate_id="C1",
        range_start=4, range_end=8, width=4,
        endian="big", signed=False,
        candidate_role=CandidateRole.TRANSITION_ENABLING,
        semantic_type=SemanticType.LENGTH,
        confidence=0.5,
        evidence={
            "pre_preserve": 0.2,
            "transition_gain": 0.8,
            "post_stability": 0.4,
            "var_match": 0.9,
            "micro_probe_gain": 0.3,
        },
    )
    score = score_field(h)
    assert 0.0 <= score <= 1.0, f"Score out of range: {score}"
    print(f"[PASS] score_field: {score:.4f}")


def test_rank_hypotheses():
    hypotheses = [
        FieldHypothesis(candidate_id="C1", range_start=0, range_end=4, width=4,
                        evidence={"pre_preserve": 0.9, "transition_gain": 0.1, "post_stability": 0.3, "var_match": 0.2}),
        FieldHypothesis(candidate_id="C2", range_start=4, range_end=8, width=4,
                        evidence={"pre_preserve": 0.2, "transition_gain": 0.8, "post_stability": 0.4, "var_match": 0.9}),
        FieldHypothesis(candidate_id="C3", range_start=8, range_end=12, width=4,
                        evidence={"pre_preserve": 0.5, "transition_gain": 0.3, "post_stability": 0.5, "var_match": 0.3}),
    ]

    ranked = rank_hypotheses(hypotheses, top_k=2)
    assert len(ranked) == 2, f"Expected 2, got {len(ranked)}"
    assert ranked[0].confidence >= ranked[1].confidence
    print(f"[PASS] rank_hypotheses: top={ranked[0].candidate_id}")


def test_classify_role():
    h = FieldHypothesis(
        candidate_id="C1", range_start=0, range_end=4, width=4,
        evidence={"pre_preserve": 0.9, "transition_gain": 0.1, "post_stability": 0.3},
    )
    role = classify_role(h)
    assert role == CandidateRole.PRE_PRESERVING
    print(f"[PASS] classify_role: {role.value}")


if __name__ == "__main__":
    test_score_field()
    test_rank_hypotheses()
    test_classify_role()
    print("\nAll state_conditioned_scoring tests passed!")
