from .schemas import FieldHypothesis, CandidateRole
from typing import List, Dict


def score_field(hypothesis: FieldHypothesis,
                alpha: float = 0.2,
                beta: float = 0.3,
                gamma: float = 0.2,
                delta: float = 0.2,
                eta: float = 0.1) -> float:
    evidence = hypothesis.evidence
    pre_preserve = evidence.get("pre_preserve", 0.0)
    transition_gain = evidence.get("transition_gain", 0.0)
    post_stability = evidence.get("post_stability", 0.0)
    var_match = evidence.get("var_match", 0.0)
    micro_probe_gain = evidence.get("micro_probe_gain", 0.0)

    return (alpha * pre_preserve +
            beta * transition_gain +
            gamma * post_stability +
            delta * var_match +
            eta * micro_probe_gain)


def rank_hypotheses(hypotheses: List[FieldHypothesis],
                    top_k: int = 5) -> List[FieldHypothesis]:
    for h in hypotheses:
        h.confidence = score_field(h)
    hypotheses.sort(key=lambda h: h.confidence, reverse=True)
    return hypotheses[:top_k]


def classify_role(hypothesis: FieldHypothesis) -> CandidateRole:
    evidence = hypothesis.evidence
    pre_preserve = evidence.get("pre_preserve", 0.0)
    transition_gain = evidence.get("transition_gain", 0.0)
    post_stability = evidence.get("post_stability", 0.0)

    scores = {
        CandidateRole.PRE_PRESERVING: pre_preserve,
        CandidateRole.TRANSITION_ENABLING: transition_gain,
        CandidateRole.POST_STABILIZING: post_stability,
    }

    best_role = max(scores, key=scores.get)
    if scores[best_role] < 0.1:
        return CandidateRole.UNKNOWN
    return best_role
