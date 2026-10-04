#!/usr/bin/env python3
"""
FTFuzz Action DSL Opcode Registry (Stage: LLM Action DSL)

Defines all allowed opcodes LLM can use in action plans.
Compiler validates against this registry; mutator implements a subset.
"""

from enum import Enum, auto

# ── Slot Discovery ──
FIND_START_TAG_ATTR_SLOT    = "FIND_START_TAG_ATTR_SLOT"
FIND_CONTAINER_INSERT_SLOT  = "FIND_CONTAINER_INSERT_SLOT"
FIND_TAIL_INSERT_SLOT       = "FIND_TAIL_INSERT_SLOT"
FIND_REGION_BY_ROLE         = "FIND_REGION_BY_ROLE"

# ── Checks ──
CHECK_SLOT_NOT_IN_CLOSING_TAG = "CHECK_SLOT_NOT_IN_CLOSING_TAG"
CHECK_SLOT_NOT_IN_COMMENT     = "CHECK_SLOT_NOT_IN_COMMENT"
CHECK_SLOT_NOT_IN_CDATA       = "CHECK_SLOT_NOT_IN_CDATA"
CHECK_ATTR_ABSENT_IN_TAG      = "CHECK_ATTR_ABSENT_IN_TAG"
CHECK_TOKEN_ABSENT_IN_REGION  = "CHECK_TOKEN_ABSENT_IN_REGION"
CHECK_LOCAL_BOUNDARY_INTACT   = "CHECK_LOCAL_BOUNDARY_INTACT"

# ── Value / Name Generation ──
GEN_IDENTIFIER_VALUE      = "GEN_IDENTIFIER_VALUE"
GEN_FRESH_NAME            = "GEN_FRESH_NAME"
GEN_EXISTING_NAME_VARIANT = "GEN_EXISTING_NAME_VARIANT"

# ── Mutation / Construction ──
INSERT_ATTRIBUTE              = "INSERT_ATTRIBUTE"
INSERT_FIELD                  = "INSERT_FIELD"
INSERT_REGION_AT_SLOT         = "INSERT_REGION_AT_SLOT"
CREATE_PAIRED_DELIMITED_REGION = "CREATE_PAIRED_DELIMITED_REGION"
CREATE_SELF_CONTAINED_REGION  = "CREATE_SELF_CONTAINED_REGION"
CREATE_FIELD_SLOT_IN_REGION_HEADER = "CREATE_FIELD_SLOT_IN_REGION_HEADER"
INSERT_ELEMENT_PAIR_WITH_FIELD = "INSERT_ELEMENT_PAIR_WITH_FIELD"

# ── Control Flow ──
ON_FAIL_GOTO  = "ON_FAIL_GOTO"
ABORT_ACTION  = "ABORT_ACTION"
DONE          = "DONE"

# ── Legacy (allowed only for non-internal_table barriers) ──
PRESERVE_REGION       = "PRESERVE_REGION"
DELETE_REGION         = "DELETE_REGION"
EMPTY_REGION          = "EMPTY_REGION"
REMOVE_TOKENS         = "REMOVE_TOKENS"
FORBID_TOKENS         = "FORBID_TOKENS"
INSERT_TOKEN_IN_REGION = "INSERT_TOKEN_IN_REGION"
FOCUS_RANGE_HAVOC     = "FOCUS_RANGE_HAVOC"

# ── Registration ──
ALL_DSL_OPS = {
    # Slot Discovery
    FIND_START_TAG_ATTR_SLOT, FIND_CONTAINER_INSERT_SLOT,
    FIND_TAIL_INSERT_SLOT, FIND_REGION_BY_ROLE,
    # Checks
    CHECK_SLOT_NOT_IN_CLOSING_TAG, CHECK_SLOT_NOT_IN_COMMENT,
    CHECK_SLOT_NOT_IN_CDATA, CHECK_ATTR_ABSENT_IN_TAG,
    CHECK_TOKEN_ABSENT_IN_REGION, CHECK_LOCAL_BOUNDARY_INTACT,
    # Value/Name Generation
    GEN_IDENTIFIER_VALUE, GEN_FRESH_NAME, GEN_EXISTING_NAME_VARIANT,
    # Mutation/Construction
    INSERT_ATTRIBUTE, INSERT_FIELD, INSERT_REGION_AT_SLOT,
    CREATE_PAIRED_DELIMITED_REGION, CREATE_SELF_CONTAINED_REGION,
    CREATE_FIELD_SLOT_IN_REGION_HEADER, INSERT_ELEMENT_PAIR_WITH_FIELD,
    # Control Flow
    ON_FAIL_GOTO, ABORT_ACTION, DONE,
    # Legacy
    PRESERVE_REGION, DELETE_REGION, EMPTY_REGION,
    REMOVE_TOKENS, FORBID_TOKENS, INSERT_TOKEN_IN_REGION,
    FOCUS_RANGE_HAVOC,
}

# Ops forbidden for internal_table_materialization barriers
FORBIDDEN_FOR_INTERNAL_TABLE = {
    INSERT_TOKEN_IN_REGION, REMOVE_TOKENS, FORBID_TOKENS,
}

# Ops that ARE raw-token-based and should be rejected for structured barriers
RAW_TOKEN_OPS = {INSERT_TOKEN_IN_REGION, REMOVE_TOKENS, FORBID_TOKENS}

# MVP ops implemented in C mutator for this stage
MVP_IMPLEMENTED = {
    FIND_START_TAG_ATTR_SLOT, FIND_CONTAINER_INSERT_SLOT,
    CHECK_SLOT_NOT_IN_CLOSING_TAG, CHECK_SLOT_NOT_IN_COMMENT,
    CHECK_SLOT_NOT_IN_CDATA, CHECK_ATTR_ABSENT_IN_TAG,
    GEN_IDENTIFIER_VALUE, GEN_FRESH_NAME,
    INSERT_ATTRIBUTE, INSERT_ELEMENT_PAIR_WITH_FIELD,
    ABORT_ACTION, DONE,
}

# Op parameter specifications
OP_PARAMS = {
    FIND_START_TAG_ATTR_SLOT: {
        'required': [],
        'optional': ['prefer_ranges', 'allow_self_closing_tag', 'allow_root_tag'],
    },
    FIND_CONTAINER_INSERT_SLOT: {
        'required': [],
        'optional': ['prefer_before_tail', 'prefer_inside_existing_container', 'avoid_preserve_ranges'],
    },
    INSERT_ATTRIBUTE: {
        'required': ['attr_name', 'attr_value_ref', 'literal_format'],
        'optional': ['slot_ref'],
    },
    INSERT_ELEMENT_PAIR_WITH_FIELD: {
        'required': ['element_name_ref', 'field_name', 'field_value_ref', 'literal_format'],
        'optional': ['slot_ref'],
    },
    GEN_IDENTIFIER_VALUE: {
        'required': [],
        'optional': ['prefix', 'unique_within_seed', 'quote_wrapped', 'identifier_like'],
    },
    GEN_FRESH_NAME: {
        'required': [],
        'optional': ['prefix', 'identifier_like'],
    },
    CHECK_ATTR_ABSENT_IN_TAG: {
        'required': ['attr_name'],
        'optional': ['slot_ref'],
    },
    CHECK_SLOT_NOT_IN_CLOSING_TAG: {'required': [], 'optional': ['slot_ref']},
    CHECK_SLOT_NOT_IN_COMMENT: {'required': [], 'optional': ['slot_ref']},
    CHECK_SLOT_NOT_IN_CDATA: {'required': [], 'optional': ['slot_ref']},
}


def get_params(op):
    """Return (required_params, optional_params) for an opcode."""
    spec = OP_PARAMS.get(op, {'required': [], 'optional': []})
    return spec.get('required', []), spec.get('optional', [])


def is_mvp(op):
    return op in MVP_IMPLEMENTED


def is_raw_token_op(op):
    return op in RAW_TOKEN_OPS
