#ifndef MUTATION_POLICY_H
#define MUTATION_POLICY_H

#include <stdint.h>
#include <stddef.h>

#define MAX_PRESERVE_RANGES 32
#define MAX_FOCUS_RANGES 32
#define MAX_NUMERIC_FIELDS 32
#define MAX_DICT_TOKENS 64
#define MAX_REPAIR_RULES 16
#define MAX_TOKEN_BYTES 64
#define MAX_ACTIONS 8

typedef struct {
    uint32_t start;
    uint32_t end;
    double weight;
    char reason[64];
} preserve_range_t;

typedef struct {
    uint32_t start;
    uint32_t end;
    double weight;
    char role[64];
} focus_range_t;

typedef enum {
    ACTION_INC = 0,
    ACTION_DEC,
    ACTION_RANDOM_DELTA,
    ACTION_BOUNDARY,
    ACTION_FIT_RHS,
} numeric_action_e;

typedef struct {
    uint32_t start;
    uint32_t end;
    uint32_t width;
    char endian[8];
    int is_signed;
    char role[64];
    numeric_action_e actions[MAX_ACTIONS];
    uint32_t num_actions;
    double confidence;
} numeric_field_t;

typedef struct {
    uint8_t bytes[MAX_TOKEN_BYTES];
    uint32_t len;
    double weight;
    char reason[64];
} dict_token_t;

typedef struct {
    double numeric_boundary;
    double directional_arithmetic;
    double byte_pattern_insert;
    double repair;
    double fallback;
} operator_weights_t;

typedef enum {
    REPAIR_LENGTH_RECOMPUTE = 0,
    REPAIR_PAYLOAD_SIZE_FIT,
    REPAIR_CHECKSUM_NOOP,
} repair_type_e;

typedef struct {
    repair_type_e type;
    uint32_t length_start;
    uint32_t length_end;
    uint32_t payload_start;
    uint32_t payload_end;
    char endian[8];
} repair_rule_t;

typedef struct {
    char policy_id[128];
    uint32_t version;
    int enabled;
    char transition_id[128];
    char pre_state_id[128];
    char post_state_id[128];
    char barrier_id[128];
    char required_barrier_id[128];
    uint32_t min_pre_hits;
    double max_stsr;
    char seed_state[32];
    preserve_range_t preserve_ranges[MAX_PRESERVE_RANGES];
    uint32_t num_preserve_ranges;
    focus_range_t focus_ranges[MAX_FOCUS_RANGES];
    uint32_t num_focus_ranges;
    numeric_field_t numeric_fields[MAX_NUMERIC_FIELDS];
    uint32_t num_numeric_fields;
    dict_token_t dict_tokens[MAX_DICT_TOKENS];
    uint32_t num_dict_tokens;
    operator_weights_t op_weights;
    repair_rule_t repair_rules[MAX_REPAIR_RULES];
    uint32_t num_repair_rules;
    uint32_t max_trials;
    int downgrade_on_no_gain;
} mutation_policy_t;

#endif
