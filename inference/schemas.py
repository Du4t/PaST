from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class CandidateRole(Enum):
    PRE_PRESERVING = "pre_preserving"
    TRANSITION_ENABLING = "transition_enabling"
    POST_STABILIZING = "post_stabilizing"
    UNKNOWN = "unknown"


class SemanticType(Enum):
    LENGTH = "length"
    COUNT = "count"
    OFFSET = "offset"
    MAGIC = "magic"
    TYPE = "type"
    CHECKSUM = "checksum"
    UNKNOWN = "unknown"


@dataclass
class FieldHypothesis:
    candidate_id: str
    range_start: int
    range_end: int
    width: int
    endian: str = "big"
    signed: bool = False
    candidate_role: CandidateRole = CandidateRole.UNKNOWN
    semantic_type: SemanticType = SemanticType.UNKNOWN
    confidence: float = 0.0
    evidence: Dict[str, float] = field(default_factory=dict)


@dataclass
class FieldInferenceResult:
    transition_id: str
    barrier_id: str
    hypotheses: List[FieldHypothesis] = field(default_factory=list)
    timestamp: float = 0.0


@dataclass
class MicroProbeResult:
    candidate_id: str
    perturbation: int
    pre_state_preserved: bool
    distance_change: int
    post_state_reached: bool
    crash_detected: bool
