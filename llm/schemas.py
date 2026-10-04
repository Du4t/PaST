from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class MutationAction(Enum):
    INC = "inc"
    DEC = "dec"
    RANDOM_DELTA = "random_delta"
    BOUNDARY = "boundary"
    FIT_RHS = "fit_rhs"
    PRESERVE = "preserve"
    DICT_INSERT = "dict_insert"


@dataclass
class ResolvedField:
    candidate_id: str
    range_start: int
    range_end: int
    width: int
    endian: str
    signed: bool
    role: str
    semantic_type: str
    actions: List[str] = field(default_factory=list)
    preserve: bool = False
    focus: bool = False
    confidence: float = 0.0
    rationale: str = ""


@dataclass
class ResolverOutput:
    transition_id: str
    barrier_id: str
    selected_fields: List[ResolvedField] = field(default_factory=list)
    preserve_ranges: List[Dict] = field(default_factory=list)
    focus_ranges: List[Dict] = field(default_factory=list)
    dictionary_tokens: List[Dict] = field(default_factory=list)
    repair_suggestions: List[Dict] = field(default_factory=list)
    overall_confidence: float = 0.0
    rationale_summary: str = ""
