#ifndef MUTATION_POLICY_LOADER_H
#define MUTATION_POLICY_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* ---- constants ---- */
#define FTFUZZ_MAX_POLICIES            16   /* was 128 — actual usage 0-3  */
#define FTFUZZ_MAX_POLICY_GROUPS        8   /* was 128 — actual usage 1-3  */
#define FTFUZZ_MAX_TRANSITION_MAPPINGS 512  /* was 4096 — actual usage <100 */
#define FTFUZZ_MAX_TOKEN_COUNT         32   /* was 128 — actual usage 0-5  */
#define FTFUZZ_MAX_TOKEN_LEN           128
#define FTFUZZ_MAX_TRANSITION_ID       128
#define FTFUZZ_MAX_ID_LEN              128
#define FTFUZZ_MAX_STATE_CLASSES       8
#define FTFUZZ_MAX_MEMBERS_PER_GROUP   16   /* was 256 — actual usage 1-5  */
#define FTFUZZ_LOADER_PATH_MAX         512
#define FTFUZZ_MAX_STATE_IDS           1024  /* was 4096 — fits in SHM limit */
#define FTFUZZ_MAX_RANGES_PER_GROUP     8   /* was 64  — actual usage 0-2  */
#define FTFUZZ_MAX_EDIT_OPS            16   /* was 32  — actual usage 3-8  */
#define FTFUZZ_MAX_EDIT_TEXT            128
#define FTFUZZ_MAX_ONTOLOGY_ACTIONS     8   /* was 64  — actual usage 0    */
#define FTFUZZ_MAX_FORBIDDEN_TOKENS      8   /* was 64  — actual usage 0    */

/* Stage 2.7: Donor rebase, scaffold, preserve mask */
#define FTFUZZ_MAX_PRECONDITION_TOKENS    8  /* was 32  — actual usage 0-5  */
#define FTFUZZ_MAX_SCAFFOLD_TEMPLATE   2048  /* was 4096 */
#define FTFUZZ_MAX_PRESERVE_MASK_RANGES   8  /* was 64  — actual usage 0    */
#define FTFUZZ_MAX_DONOR_SCAN_DEFAULT    5000
#define FTFUZZ_MAX_FIND_REFS             16
#define FTFUZZ_MAX_PARAM_VALUE_LEN       256
#define FTFUZZ_MAX_OP_PARAMS             12

/* ---- byte range types ---- */
typedef struct {
    uint32_t start;
    uint32_t end;
    uint32_t length;
    double confidence;
    char role[128];
} ftfuzz_byte_range_t;

typedef struct {
    char op[FTFUZZ_MAX_EDIT_TEXT];
    char target[FTFUZZ_MAX_EDIT_TEXT];
    char purpose[FTFUZZ_MAX_EDIT_TEXT];
    double weight;
} ftfuzz_semantic_edit_op_t;

/* Stage 2.7: runtime preserve mask tracking (per-execution, not in store) */
typedef struct {
    uint32_t start;
    uint32_t end;
    uint32_t protection;
    char role[64];
    char source_step[FTFUZZ_MAX_ID_LEN];
} ftfuzz_preserve_mask_range_t;

typedef struct {
    int enabled;
    float max_protected_ratio;
    size_t range_count;
    ftfuzz_preserve_mask_range_t ranges[FTFUZZ_MAX_PRESERVE_MASK_RANGES];
} ftfuzz_preserve_mask_t;

/* ---- ontology action (Stage 2.3-pre) ---- */
typedef struct {
    char action_id[FTFUZZ_MAX_ID_LEN];
    char source_atom[FTFUZZ_MAX_ID_LEN];
    char op[64];             /* PRESERVE_REGION, DELETE_REGION, etc. */
    char region_role[64];    /* declaration_region, constraint_region, etc. */
    char scope[64];          /* focus_range_or_token_scan, whole_seed_fallback */
    double confidence;
    size_t evidence_token_count;
    char evidence_tokens[FTFUZZ_MAX_TOKEN_COUNT][FTFUZZ_MAX_TOKEN_LEN];
} ftfuzz_ontology_action_t;

/* ---- Stage 2.7: Donor rebase, scaffold, preserve mask types ---- */

typedef struct {
    int enabled;
    int require_path_relevance;
    uint32_t max_donor_scan;
    double anchor_satisfaction_weight;
    double frontier_survival_weight;
    double path_relevance_weight;
} ftfuzz_donor_rebase_policy_t;

typedef struct {
    int enabled;
    uint32_t default_protection;  /* 0=no_havoc, 1=low_havoc, 2=no_delete, 3=no_insert_inside, 4=repair_only */
    int protect_inserted_ranges;
    int protect_binding_keys;
    float max_protected_ratio;
} ftfuzz_preserve_mask_policy_t;

/* ---- v2 policy group types ---- */

typedef struct {
    char token[FTFUZZ_MAX_TOKEN_LEN];
    int  token_len;           /* binary-safe byte length */
    char source[64];
} ftfuzz_policy_token_t;

/* Bytecode plan: offset reference resolved from FIND operations */
typedef struct {
    char name[32];
    uint32_t offset;       /* resolved absolute offset in buffer */
    int found;             /* 1 = pattern was found, 0 = not found */
} ftfuzz_find_ref_t;

/* Action chain step (from relation_plan_compiler, format-agnostic)
 * Extended with bytecode_plan.v1 support: named params map for
 * variable-width operations (FIND, WRITE, INSERT, DELETE,
 * SET_INT, INC_INT, SIZE_TO, PRESERVE). */
typedef struct {
    int  step;
    int  source_step;
    char action_id[FTFUZZ_MAX_ID_LEN];
    char op[FTFUZZ_MAX_EDIT_TEXT];         /* FIND, WRITE, INSERT, DELETE, SET_INT, INC_INT, SIZE_TO, PRESERVE, or legacy XML ops */
    char region_role[FTFUZZ_MAX_EDIT_TEXT]; /* target region description (legacy) */
    char relation_id[FTFUZZ_MAX_ID_LEN];    /* (legacy) */
    int  requires_success;                  /* 1 = abort chain if this step fails */
    /* Named key-value parameters (format-agnostic, used by bytecode ops) */
    int  param_count;
    char param_keys[FTFUZZ_MAX_OP_PARAMS][64];
    char param_values[FTFUZZ_MAX_OP_PARAMS][FTFUZZ_MAX_PARAM_VALUE_LEN];
} ftfuzz_action_step_t;

typedef struct {
    char policy_group_id[FTFUZZ_MAX_ID_LEN];
    int enabled;
    double priority;
    double confidence;
    char semantic_source[64];
    char llm_model[128];
    char representative_transition[FTFUZZ_MAX_ID_LEN];

    size_t member_transition_count;
    char member_transitions[FTFUZZ_MAX_MEMBERS_PER_GROUP][FTFUZZ_MAX_ID_LEN];

    size_t dictionary_token_count;
    ftfuzz_policy_token_t dictionary_tokens[FTFUZZ_MAX_TOKEN_COUNT];

    size_t activation_state_class_count;
    char activation_state_classes[FTFUZZ_MAX_STATE_CLASSES][64];

    double op_dictionary_insert;
    double op_fallback_havoc;
    double op_region_focus;
    double op_numeric_boundary;
    double op_structure_insert;
    double op_repair;

    /* byte-window ranges */
    size_t preserve_range_count;
    ftfuzz_byte_range_t preserve_ranges[FTFUZZ_MAX_RANGES_PER_GROUP];
    size_t focus_range_count;
    ftfuzz_byte_range_t focus_ranges[FTFUZZ_MAX_RANGES_PER_GROUP];
    size_t insert_range_count;
    ftfuzz_byte_range_t insert_ranges[FTFUZZ_MAX_RANGES_PER_GROUP];

    /* semantic edit IR */
    int edit_plan_enabled;
    char edit_barrier_kind[64];
    size_t semantic_edit_op_count;
    ftfuzz_semantic_edit_op_t semantic_edit_ops[FTFUZZ_MAX_EDIT_OPS];

    /* ontology action plan (Stage 2.3-pre) */
    int desired_outcome;  /* -1=unset, 0=false, 1=true */
    char direction_source[64];
    size_t ontology_action_count;
    ftfuzz_ontology_action_t ontology_actions[FTFUZZ_MAX_ONTOLOGY_ACTIONS];
    size_t forbidden_token_count;
    char forbidden_tokens[FTFUZZ_MAX_FORBIDDEN_TOKENS][FTFUZZ_MAX_TOKEN_LEN];

    /* ── Stage 2.8: Action chain steps (from relation_plan_compiler) ── */
    size_t action_step_count;
    ftfuzz_action_step_t action_steps[FTFUZZ_MAX_EDIT_OPS];

    /* ── Stage 2.7: Donor rebase, scaffold, preserve mask ── */
    size_t precondition_token_count;
    char precondition_tokens[FTFUZZ_MAX_PRECONDITION_TOKENS][FTFUZZ_MAX_TOKEN_LEN];
    int  precondition_token_len[FTFUZZ_MAX_PRECONDITION_TOKENS];  /* binary-safe */
    char scaffold_template[FTFUZZ_MAX_SCAFFOLD_TEMPLATE];
    int scaffold_template_len;
    ftfuzz_donor_rebase_policy_t donor_rebase;
    ftfuzz_preserve_mask_policy_t preserve_mask;

    /* Bytecode plan: runtime find ref state (resolved per-execution) */
    int find_ref_count;
    ftfuzz_find_ref_t find_refs[FTFUZZ_MAX_FIND_REFS];
} ftfuzz_policy_group_t;

typedef struct {
    char transition_id[FTFUZZ_MAX_ID_LEN];
    char policy_group_id[FTFUZZ_MAX_ID_LEN];
} ftfuzz_transition_policy_mapping_t;

/* ---- legacy flat-policy types (compiler-produced stores) ---- */

typedef struct {
    char transition_id[FTFUZZ_MAX_TRANSITION_ID];
    uint64_t policy_version;
    int enabled;
    char semantic_source[32];
    char llm_model[128];
    double confidence;
    double priority;
    size_t activation_state_class_count;
    char activation_state_classes[FTFUZZ_MAX_STATE_CLASSES][64];
    size_t dictionary_token_count;
    char dictionary_tokens[FTFUZZ_MAX_TOKEN_COUNT][FTFUZZ_MAX_TOKEN_LEN];
    size_t preserve_hint_count;
    size_t focus_hint_count;
    size_t numeric_hint_count;
    size_t repair_hint_count;
    double op_dictionary_insert;
    double op_fallback_havoc;
    double op_region_focus;
    double op_numeric_boundary;
    double op_repair;
} ftfuzz_policy_entry_t;

/* ---- unified store (v2 primary + legacy compat) ---- */

typedef struct {
    uint64_t store_version;
    char schema_version[64];
    char activation_mode[64];

    /* v2 policy groups (primary path) */
    size_t policy_group_count;
    ftfuzz_policy_group_t policy_groups[FTFUZZ_MAX_POLICY_GROUPS];

    size_t transition_mapping_count;
    ftfuzz_transition_policy_mapping_t mappings[FTFUZZ_MAX_TRANSITION_MAPPINGS];

    /* legacy flat policies (fallback) */
    size_t policy_count;
    ftfuzz_policy_entry_t policies[FTFUZZ_MAX_POLICIES];
} ftfuzz_policy_store_v2_t;

/* ---- API ---- */

/* Init / reload */
int ftfuzz_policy_loader_init(const char *path);
int ftfuzz_policy_loader_reload_if_needed(void);

/* Get full store */
int ftfuzz_policy_loader_get_store(ftfuzz_policy_store_v2_t *out);

/* Seed-state-conditioned policy group selection.
 * Reads seed .ftstate.json, maps transitions -> policy_groups,
 * scores by state_class weight + group priority. */
int ftfuzz_policy_loader_select_for_seed(
    const char *seed_path,
    const char *ftstate_path,
    ftfuzz_policy_group_t *out_group,
    char *out_transition_id,
    size_t out_transition_id_size,
    char *out_state_class,
    size_t out_state_class_size);

/* Direct group lookup by id */
int ftfuzz_policy_loader_get_group_by_id(
    const char *policy_group_id,
    ftfuzz_policy_group_t *out_group);

void ftfuzz_policy_loader_destroy(void);

/* State map: converts numeric state_id (from .ftstate.json sidecar) to
 * transition_id (used in policy_store transition_to_policy_group).
 * Loads state_map.csv via FTFUZZ_STATE_MAP env var. */
int ftfuzz_state_map_load(const char *path);
int ftfuzz_state_map_lookup(int state_id, char *out_transition_id, size_t size);

#endif
