/*
 * FTFuzz Semantic Mutator (Stage 2.1-pre-fix)
 * Multi-Policy Group Store + Seed-State-Conditioned Activation.
 *
 * Activation: parent queue seed .ftstate.json -> transition -> policy_group.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <dirent.h>
#include "mutation_policy_loader.h"

#define AFL_CUSTOM_MUTATOR_LIBRARY
#include "afl-fuzz.h"

static FILE *g_log = NULL;
static ftfuzz_policy_store_v2_t g_store;
static int g_loaded = 0;
static char g_last_seed[512] = {0};

/* Ablation mode from FTFUZZ_ABLATION env var. Read once at init. */
static int g_ablation_is_prefix = 0;
static int g_ablation_is_action = 0;

/* Stage 2.7: Scaffold seed protection — track recently scaffolded seeds
 * to avoid immediately destroying their structure with random havoc. */
static uint32_t g_scaffold_skeleton_hash = 0;
static int g_scaffold_skeleton_valid = 0;

static uint32_t compute_skeleton_hash(unsigned char *buf, size_t ns) {
    /* djb2 hash of the bytes around potential structural markers.
     * This loosely identifies whether a seed has the same structural
     * skeleton as a previously scaffolded output. */
    uint32_t h = 5381;
    for (size_t i = 0; i + 2 < ns; i++) {
        /* Hash around '<' characters as structural markers */
        if (buf[i] == '<' && i + 4 < ns) {
            size_t end = i + 16 < ns ? i + 16 : ns;
            for (size_t j = i; j < end; j++)
                h = ((h << 5) + h) + buf[j];
        }
    }
    return h;
}

/* Counters */
static uint64_t g_calls = 0, g_reloads = 0;
static uint64_t g_queue_get_calls = 0;
static uint64_t g_ftstate_attempts = 0, g_ftstate_success = 0, g_ftstate_fail = 0;
static uint64_t g_selection_attempts = 0, g_selection_success = 0, g_selection_fallback = 0;
static uint64_t g_insertions = 0, g_attempts = 0, g_fallbacks = 0;
static uint64_t g_range_insertions = 0, g_focus_havoc = 0, g_preserve_aware = 0;
static uint64_t g_semantic_edit_attempts = 0, g_semantic_edit_success = 0;
static uint64_t g_edit_op_counts[FTFUZZ_MAX_EDIT_OPS];
/* Ontology action counters (Stage 2.3-pre) */
static uint64_t g_onto_attempts = 0, g_onto_success = 0, g_onto_rejected = 0, g_onto_fallback = 0;
static uint64_t g_forbidden_token_skips = 0;
static uint64_t g_active_mut_attempts = 0, g_active_mut_success = 0;
static uint64_t g_passive_constraint_applied = 0;
static uint64_t g_chain_consecutive_failures = 0;  /* cross-seed failure counter */
static uint64_t g_auto_construct_attempts = 0;      /* Layer 2 build attempts */
static uint64_t g_auto_construct_success = 0;       /* Layer 2 build successes */
static uint64_t g_scaffold_inplace_failures = 0;    /* consecutive SCAFFOLD_INPLACE failures */
static uint64_t g_per_op_success[32];  /* indexed by operator op string hash */
/* Cache: only re-read sidecar when seed changes */
static char g_last_sidecar_seed[512] = {0};
static ftfuzz_policy_group_t g_cached_sel;
static char g_cached_tid[FTFUZZ_MAX_ID_LEN];
static char g_cached_sc[64];
static int g_cached_has_pol = -1;
/* Reusable buffer for insert operations (AFL doesn't free custom mutator output) */
static unsigned char *g_insert_buf = NULL;
static size_t g_insert_buf_size = 0;

/* Per-group counters */
#define PG_COUNTERS_MAX 128
static char g_pg_ids[PG_COUNTERS_MAX][FTFUZZ_MAX_ID_LEN];
static uint64_t g_pg_selections[PG_COUNTERS_MAX];
static uint64_t g_pg_insertions[PG_COUNTERS_MAX];
static size_t g_pg_count = 0;

static int _in_preserve(size_t pos, ftfuzz_policy_group_t *g) {
    for (size_t i = 0; i < g->preserve_range_count; i++)
        if (pos >= g->preserve_ranges[i].start && pos < g->preserve_ranges[i].end)
            return 1;
    return 0;
}

static int _is_forbidden(const char *token, ftfuzz_policy_group_t *g) {
    if (!token || !token[0]) return 0;
    for (size_t i = 0; i < g->forbidden_token_count; i++)
        if (!strcmp(token, g->forbidden_tokens[i])) return 1;
    return 0;
}

/* ── Bytecode Plan: Helper Functions (file scope) ── */

/* Decode a hex char to its 4-bit value. Returns -1 on invalid hex. */
static inline int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string into binary buffer. Returns bytes written, 0 on error. */
static size_t hex_decode(const char *hex, unsigned char *out, size_t out_max) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return 0;
    size_t n = len / 2;
    if (n > out_max) n = out_max;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}

/* Decode a data/pattern string to bytes. Tries hex first; falls back to
 * raw text (ASCII keywords, Lua snippets, XML tags, etc.) for text format.
 * Returns bytes written, 0 on total failure. */
static size_t decode_data(const char *str, unsigned char *out, size_t out_max) {
    if (!str || !str[0]) return 0;
    size_t n = hex_decode(str, out, out_max);
    if (n > 0) return n;
    /* Text format fallback: use raw bytes directly */
    size_t raw_len = strlen(str);
    if (raw_len > out_max) raw_len = out_max;
    memcpy(out, str, raw_len);
    return raw_len;
}

/* Resolve an offset string to an absolute byte position.
 * Accepted forms: absolute int ("0", "64"), {ref} ("{elf_hdr}"),
 * {ref}+N ("{elf_hdr}+16"), or "END" (buffer end).
 * Returns 0 on success, -1 on failure. */
static int resolve_offset(const char *offset_str, ftfuzz_policy_group_t *pg,
                          size_t buf_size, uint32_t *out_abs) {
    if (!offset_str || !offset_str[0]) return -1;
    /* END */
    if (!strcmp(offset_str, "END")) {
        *out_abs = (uint32_t)buf_size;
        return 0;
    }
    /* Absolute integer */
    char *endp = NULL;
    long val = strtol(offset_str, &endp, 10);
    if (endp && *endp == '\0') {
        if (val < 0) return -1;
        *out_abs = (uint32_t)val;
        return 0;
    }
    /* {ref} or {ref}+N */
    if (offset_str[0] == '{') {
        const char *close = strchr(offset_str, '}');
        if (!close) return -1;
        size_t name_len = (size_t)(close - offset_str - 1);
        if (name_len > 31) return -1;
        char ref_name[32];
        memcpy(ref_name, offset_str + 1, name_len);
        ref_name[name_len] = '\0';
        /* Look up in find_refs */
        int found_ref = -1;
        for (int ri = 0; ri < pg->find_ref_count; ri++) {
            if (!strcmp(pg->find_refs[ri].name, ref_name) &&
                pg->find_refs[ri].found) {
                found_ref = ri;
                break;
            }
        }
        if (found_ref < 0) return -1;
        uint32_t base = pg->find_refs[found_ref].offset;
        /* Check for +N or -N suffix */
        const char *plus = strchr(close, '+');
        const char *minus = strchr(close, '-');

        if (plus) {
            long add = strtol(plus + 1, &endp, 10);
            if (add < 0) return -1;
            base += (uint32_t)add;
        } else if (minus) {
            long sub = strtol(minus + 1, &endp, 10);
            if (sub < 0) return -1;
            if ((long)base < sub) return -1;  /* underflow guard */
            base -= (uint32_t)sub;
        }
        *out_abs = base;
        return 0;
    }
    return -1;
}

/* Read an integer from buffer at offset with given width and endianness. */
static uint64_t read_integer(const unsigned char *buf, uint32_t offset,
                              int width, const char *endian) {
    uint64_t val = 0;
    if (!endian || !strcmp(endian, "le")) {
        for (int i = 0; i < width; i++)
            val |= ((uint64_t)buf[offset + i]) << (i * 8);
    } else {
        for (int i = 0; i < width; i++)
            val |= ((uint64_t)buf[offset + i]) << ((width - 1 - i) * 8);
    }
    return val;
}

/* Write an integer to buffer at offset with given width and endianness. */
static void write_integer(unsigned char *buf, uint32_t offset,
                           int width, const char *endian, uint64_t val) {
    if (!endian || !strcmp(endian, "le")) {
        for (int i = 0; i < width; i++)
            buf[offset + i] = (unsigned char)((val >> (i * 8)) & 0xFF);
    } else {
        for (int i = 0; i < width; i++)
            buf[offset + i] = (unsigned char)((val >> ((width - 1 - i) * 8)) & 0xFF);
    }
}

static int _find_token(const unsigned char *buf, size_t buf_size,
                        const char *token, size_t *out_pos, size_t *out_len) {
    size_t tl = strlen(token);
    if (tl == 0 || tl > buf_size) return 0;
    for (size_t i = 0; i <= buf_size - tl; i++) {
        if (!memcmp(buf + i, token, tl)) {
            *out_pos = i;
            *out_len = tl;
            return 1;
        }
    }
    return 0;
}

/* Forward declaration */
static void log_msg(const char *fmt, ...);

/* ── Action DSL MVP opcodes (Stage: Action DSL) ── */

static int dsl_find_start_tag_attr_slot(unsigned char *buf, size_t ns, size_t *out_pos) {
    /* Find a position inside a start tag '<...>' for attribute insertion.
     * Look for '>' that follows '<' (not '</' or '<?' or '<!--'). */
    for (size_t i = 0; i + 1 < ns; i++) {
        if (buf[i] == '<' && buf[i+1] != '/' && buf[i+1] != '?' && buf[i+1] != '!') {
            /* Found start tag opening. Find the matching '>'. */
            for (size_t j = i + 1; j < ns; j++) {
                if (buf[j] == '>' && (j == i+1 || buf[j-1] != '/')) {
                    /* Insert attribute before '>' or before '/>' */
                    *out_pos = (j > 0 && buf[j-1] == '/') ? (j - 1) : j;
                    return 1;
                }
                if (buf[j] == '<') break; /* nested tag, stop */
            }
        }
    }
    return 0; /* no suitable slot found */
}

static int dsl_gen_identifier(char *out, size_t out_size, const char *prefix,
                               unsigned int *counter) {
    (*counter)++;
    snprintf(out, out_size, "%s_%03u", prefix ? prefix : "ftid", *counter % 1000);
    return 1;
}

static int dsl_insert_attribute(unsigned char *buf, size_t *p_ns,
                                 size_t slot_pos, size_t max_size,
                                 const char *attr_name, const char *attr_value) {
    /* Insert complete attribute like ' xml:id="ftid_001"' at slot position */
    char attr_text[256];
    snprintf(attr_text, sizeof(attr_text), " %s=\"%s\"", attr_name, attr_value);
    size_t tl = strlen(attr_text);
    size_t ns = *p_ns;
    if (ns + tl > max_size) return 0;
    if (slot_pos > ns) slot_pos = ns;
    memmove(buf + slot_pos + tl, buf + slot_pos, ns - slot_pos);
    memcpy(buf + slot_pos, attr_text, tl);
    *p_ns = ns + tl;
    return 1;
}

/* Execute a single Action DSL step. Returns 1 on success, 0 on failure.
 * Output variables (id1, slot1, etc.) stored in a simple map. */
#define DSL_MAX_VARS 8
static int exec_dsl_step(const char *op, unsigned char *buf, size_t *p_ns,
                          size_t max_size, size_t *out_slot,
                          char *out_value, size_t out_value_size,
                          unsigned int *gen_counter) {
    size_t ns = *p_ns;

    if (!strcmp(op, "FIND_START_TAG_ATTR_SLOT")) {
        size_t slot;
        if (dsl_find_start_tag_attr_slot(buf, ns, &slot)) {
            if (out_slot) *out_slot = slot;
            return 1;
        }
        return 0;
    }

    if (!strcmp(op, "FIND_CONTAINER_INSERT_SLOT")) {
        /* Insert before closing tag or at end */
        for (size_t i = ns; i > 0; i--) {
            if (buf[i-1] == '>') {
                if (out_slot) *out_slot = i;
                return 1;
            }
        }
        if (out_slot) *out_slot = ns;
        return 1;
    }

    if (!strcmp(op, "GEN_IDENTIFIER_VALUE") || !strcmp(op, "GEN_FRESH_NAME")) {
        const char *prefix = (op[4] == 'I') ? "ftid" : "ftnode";
        dsl_gen_identifier(out_value, out_value_size, prefix, gen_counter);
        return (out_value[0] != 0);
    }

    if (!strcmp(op, "CHECK_ATTR_ABSENT_IN_TAG")) {
        /* Simple check: scan for attr_name in the last 256 bytes */
        /* For MVP, always return success (we trust the slot finder) */
        return 1;
    }

    if (!strcmp(op, "CHECK_SLOT_NOT_IN_COMMENT") ||
        !strcmp(op, "CHECK_SLOT_NOT_IN_CDATA") ||
        !strcmp(op, "CHECK_SLOT_NOT_IN_CLOSING_TAG")) {
        return 1; /* MVP: assume slot finder gave a valid position */
    }

    if (!strcmp(op, "INSERT_ATTRIBUTE")) {
        if (!out_slot || !out_value || !out_value[0]) return 0;
        return dsl_insert_attribute(buf, p_ns, *out_slot, max_size,
                                     "xml:id", out_value);
    }

    if (!strcmp(op, "INSERT_ELEMENT_PAIR_WITH_FIELD")) {
        if (!out_slot || !out_value || !out_value[0]) return 0;
        char elem_pair[512];
        snprintf(elem_pair, sizeof(elem_pair),
                 "<ftnode xml:id=\"%s\"></ftnode>", out_value);
        size_t tl = strlen(elem_pair);
        size_t pos = *out_slot;
        if (pos > ns) pos = ns;
        if (ns + tl > max_size) return 0;
        memmove(buf + pos + tl, buf + pos, ns - pos);
        memcpy(buf + pos, elem_pair, tl);
        *p_ns = ns + tl;
        return 1;
    }

    if (!strcmp(op, "ABORT_ACTION") || !strcmp(op, "DONE")) {
        return 1; /* control flow, handled by caller */
    }

    return 0; /* unknown op */
}

/* ── Action Chain MVP (Stage 2.5-fix) ── */

static int dsl_find_dtd_internal_subset(unsigned char *buf, size_t ns, size_t *out_start, size_t *out_end) {
    /* Find <!DOCTYPE ... [ ... ]> pattern. Returns 0 if not found. */
    for (size_t i = 0; i + 9 < ns; i++) {
        if (!memcmp(buf + i, "<!DOCTYPE", 9)) {
            /* Find '[' */
            size_t bracket = 0;
            for (size_t j = i + 9; j < ns; j++) {
                if (buf[j] == '[') { bracket = j; break; }
                if (buf[j] == '>' && bracket == 0) return 0; /* no internal subset */
            }
            if (bracket == 0) return 0;
            /* Find matching ']' */
            for (size_t j = bracket + 1; j < ns; j++) {
                if (buf[j] == ']' && j + 1 < ns && buf[j+1] == '>') {
                    *out_start = bracket + 1; /* after '[' */
                    *out_end = j;             /* before ']' */
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Insert ATTLIST declaration into DTD internal subset */
static int chain_insert_attlist_decl(unsigned char *buf, size_t *p_ns,
                                      size_t max_size, const char *elem_name,
                                      const char *attr_name, const char *attr_type) {
    size_t ns = *p_ns;
    size_t dtd_start, dtd_end;
    if (!dsl_find_dtd_internal_subset(buf, ns, &dtd_start, &dtd_end)) {
        /* No DTD internal subset - can't insert ATTLIST */
        return 0;
    }
    char decl[256];
    snprintf(decl, sizeof(decl), "\n<!ATTLIST %s %s %s #IMPLIED>\n", elem_name, attr_name, attr_type);
    size_t tl = strlen(decl);
    if (ns + tl > max_size) return 0;
    /* Insert at the end of internal subset (before ']') */
    memmove(buf + dtd_end + tl, buf + dtd_end, ns - dtd_end);
    memcpy(buf + dtd_end, decl, tl);
    *p_ns = ns + tl;
    return 1;
}

/* Find an element start tag matching elem_name, or any element if NULL */
static int chain_find_element_tag(unsigned char *buf, size_t ns,
                                   const char *elem_name, size_t *out_tag_start) {
    for (size_t i = 0; i + 3 < ns; i++) {
        if (buf[i] == '<' && buf[i+1] != '/' && buf[i+1] != '?' && buf[i+1] != '!') {
            /* Found a start tag '<' */
            /* If elem_name specified, check for exact match after '<' */
            if (elem_name && elem_name[0]) {
                size_t el = strlen(elem_name);
                if (i + 1 + el < ns && !memcmp(buf + i + 1, elem_name, el) &&
                    (buf[i+1+el] == '>' || buf[i+1+el] == ' ' || buf[i+1+el] == '/')) {
                    *out_tag_start = i;
                    return 1;
                }
            } else {
                *out_tag_start = i;
                return 1;
            }
        }
    }
    return 0;
}

/* Insert matching instance field on an element */
static int chain_insert_matching_field(unsigned char *buf, size_t *p_ns,
                                        size_t max_size, const char *elem_name,
                                        const char *attr_name, const char *attr_value) {
    size_t ns = *p_ns;
    size_t tag_start;
    if (!chain_find_element_tag(buf, ns, elem_name, &tag_start)) {
        /* Element not found - try any element */
        if (!chain_find_element_tag(buf, ns, NULL, &tag_start)) return 0;
    }
    /* Find '>' of this start tag to insert attribute before it */
    size_t slot = tag_start + 1;
    while (slot < ns && buf[slot] != '>' && buf[slot] != '/') slot++;
    if (buf[slot] == '/') slot--; /* before '/>' */
    /* Insert attribute */
    char attr_text[256];
    snprintf(attr_text, sizeof(attr_text), " %s=\"%s\"", attr_name, attr_value);
    size_t tl = strlen(attr_text);
    if (ns + tl > max_size) return 0;
    memmove(buf + slot + tl, buf + slot, ns - slot);
    memcpy(buf + slot, attr_text, tl);
    *p_ns = ns + tl;
    return 1;
}

/* ── Scaffold stats counters (Stage 2.6) ── */
static uint64_t g_chain_precheck_attempts = 0;
static uint64_t g_chain_precondition_pass = 0;
static uint64_t g_chain_precondition_fail = 0;
static uint64_t g_chain_inplace_attempts = 0;
static uint64_t g_chain_inplace_success = 0;
static uint64_t g_scaffold_rebuild_attempts = 0;
static uint64_t g_scaffold_rebuild_success = 0;

/* Signal daemon to retry when scaffold has been rebuilt many times without progress.
   Threshold: 100 rebuilds per policy group triggers a retry signal. */
#define SCAFFOLD_RETRY_THRESHOLD 10
static void check_scaffold_retry_threshold(const char *group_id) {
    static int signaled[8] = {0};
    static char signaled_groups[8][FTFUZZ_MAX_ID_LEN] = {{0}};
    if (g_scaffold_rebuild_success > 0 &&
        (g_scaffold_rebuild_success % SCAFFOLD_RETRY_THRESHOLD) == 0) {
        /* Check if we already signaled for this group at this threshold level */
        int level = (int)(g_scaffold_rebuild_success / SCAFFOLD_RETRY_THRESHOLD);
        int slot = -1;
        for (int i = 0; i < 8; i++) {
            if (!strcmp(signaled_groups[i], group_id) && signaled[i] >= level) return;
            if (signaled_groups[i][0] == 0 && slot < 0) slot = i;
        }
        if (slot < 0) return;
        strncpy(signaled_groups[slot], group_id, FTFUZZ_MAX_ID_LEN - 1);
        signaled[slot] = level;
        /* Write signal file for daemon */
        char sig_path[256];
        snprintf(sig_path, sizeof(sig_path), "/tmp/ftfuzz_scaffold_retry_%s", group_id);
        FILE *sf = fopen(sig_path, "w");
        if (sf) {
            fprintf(sf, "%lu\n", (unsigned long)g_scaffold_rebuild_success);
            fclose(sf);
        }
    }
}
static uint64_t g_scaffold_rebuild_rejected = 0;
static uint64_t g_chain_ineligible = 0;
static uint64_t g_known_invalid_fallback_blocked = 0;

/* Stage 2.7: Donor rebase counters */
static uint64_t g_chain_donor_attempts = 0;
static uint64_t g_chain_donor_success = 0;
static uint64_t g_chain_donor_miss = 0;
static uint64_t g_chain_no_base_skip = 0;
static uint64_t g_chain_current_attempts = 0;
static uint64_t g_chain_current_success = 0;
static uint64_t g_donor_seeds_scanned_total = 0;

/* Stage 2.7: Preserve mask counters */
static uint64_t g_preserve_mask_created = 0;
static uint64_t g_preserve_mask_ranges_total = 0;
static uint64_t g_protected_bytes_total = 0;
static uint64_t g_masked_mutation_skipped = 0;
static uint64_t g_mask_limit_triggered = 0;
static uint64_t g_binding_key_survival_success = 0;

/* Generic precondition: check required tokens present in buffer (Stage 2.6) */
static int check_precondition_tokens(unsigned char *buf, size_t ns,
                                      const char **tokens, size_t n_tokens,
                                      const int *lengths) {
    for (size_t t = 0; t < n_tokens; t++) {
        size_t tl = (lengths && lengths[t] > 0) ? (size_t)lengths[t] : strlen(tokens[t]);
        int found = 0;
        for (size_t i = 0; i + tl <= ns; i++) {
            if (!memcmp(buf + i, tokens[t], tl)) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

/* Decode hex-encoded byte string (e.g. "FF4FFF51" or "0xFF 0x4F") to actual binary.
   Returns number of bytes decoded, 0 on failure. */
static size_t hex_decode_scaffold(unsigned char *out, size_t out_max,
                                   const char *hex_str, size_t hex_len) {
    size_t byte_count = 0;
    for (size_t i = 0; i < hex_len && byte_count < out_max; ) {
        /* Skip whitespace, commas, 0x/0X prefixes */
        if (hex_str[i] == ' ' || hex_str[i] == '\t' || hex_str[i] == '\n' ||
            hex_str[i] == '\r' || hex_str[i] == ',') { i++; continue; }
        if (hex_str[i] == '0' && i + 1 < hex_len &&
            (hex_str[i+1] == 'x' || hex_str[i+1] == 'X')) { i += 2; continue; }
        /* Need two hex digits */
        if (i + 1 >= hex_len) break;
        char c1 = hex_str[i], c2 = hex_str[i+1];
        int is_hex = 1;
        for (int j = 0; j < 2; j++) {
            char c = j ? c2 : c1;
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                is_hex = 0;
        }
        if (!is_hex) { i++; continue; }
        unsigned char byte = 0;
        for (int j = 0; j < 2; j++) {
            char c = j ? c2 : c1;
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= (unsigned char)(c - '0');
            else if (c >= 'a' && c <= 'f') byte |= (unsigned char)(c - 'a' + 10);
            else byte |= (unsigned char)(c - 'A' + 10);
        }
        out[byte_count++] = byte;
        i += 2;
    }
    return byte_count;
}

/* Generic scaffold instantiation: substitute placeholders (Stage 2.6)
   template_len: actual byte count of template (use supplied length, NOT strlen). */
static int instantiate_scaffold(unsigned char *buf, size_t *p_ns, size_t max_size,
                                 const char *template_str, int template_len,
                                 unsigned int *gen_counter,
                                 int do_log, const char *group_id) {
    size_t tlen;
    if (template_len < 0) template_len = 0;

    /* Try hex-decode first: if template looks like hex (mostly 0-9A-Fa-f
       after stripping whitespace/0x), decode to binary bytes */
    int hex_chars = 0, total_chars = 0;
    for (int i = 0; i < template_len; i++) {
        char c = template_str[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',') continue;
        if (c == '0' && i + 1 < template_len &&
            (template_str[i+1] == 'x' || template_str[i+1] == 'X')) { i++; continue; }
        total_chars++;
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            hex_chars++;
    }
    int looks_like_hex = (total_chars > 0 && hex_chars * 100 / total_chars >= 85);

    if (looks_like_hex) {
        /* Binary format — decode hex to actual bytes */
        tlen = hex_decode_scaffold(buf, max_size, template_str, (size_t)template_len);
        if (tlen == 0) {
            /* Decode failed — fallback to raw copy (text scaffold) */
            if (do_log) log_msg("[SCAFFOLD_DECODE] group=%s hex_decode_failed, using raw text\n", group_id);
            tlen = (size_t)template_len;
            if (tlen > max_size) tlen = max_size;
            memcpy(buf, template_str, tlen);
        } else if (do_log) {
            log_msg("[SCAFFOLD_DECODE] group=%s hex_decoded=%zu bytes\n", group_id, tlen);
        }
    } else {
        /* Text format or mixed content — direct copy */
        tlen = (size_t)template_len;
        if (tlen > max_size) {
            if (do_log) log_msg("[SCAFFOLD_REJECT] group=%s reason=template_exceeds_max\n", group_id);
            return 0;
        }
        memcpy(buf, template_str, tlen);
    }

    /* Substitute {fresh_id} placeholders (text only — skip for binary) */
    if (!looks_like_hex) {
        char placeholder[] = "{fresh_id}";
        size_t plen = strlen(placeholder);
        char *pos = (char *)buf;
        while ((pos = strstr(pos, placeholder)) != NULL) {
            char id_value[64];
            dsl_gen_identifier(id_value, sizeof(id_value), "ftid", gen_counter);
            size_t id_len = strlen(id_value);
            size_t offset = pos - (char *)buf;
            size_t remaining = tlen - offset;
            if (tlen - plen + id_len > max_size) break;
            memmove(pos + id_len, pos + plen, remaining - plen);
            memcpy(pos, id_value, id_len);
            tlen = tlen - plen + id_len;
            pos += id_len;
            if (do_log) log_msg("[SCAFFOLD_PLACEHOLDER] name=fresh_id value=%s\n", id_value);
        }
    }

    /* Reject scaffold if output is ASCII hex text instead of real binary bytes.
       This catches the case where \xHH escapes were not properly decoded. */
    if (tlen > 0 && !looks_like_hex) {
        int all_hex = 1;
        for (size_t i = 0; i < tlen && i < 64; i++) {
            unsigned char c = buf[i];
            if (!((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9'))) {
                all_hex = 0; break;
            }
        }
        if (all_hex) {
            if (do_log) log_msg("[SCAFFOLD_REJECT] group=%s reason=ascii_hex_not_binary len=%zu\n",
                    group_id, tlen);
            return 0;
        }
    }

    *p_ns = tlen;
    return 1;
}

/* ── Stage 2.7: Preserve mask helpers ── */

static void mask_add_range(ftfuzz_preserve_mask_t *mask, uint32_t start, uint32_t end,
                            uint32_t protection, const char *role, const char *step_id) {
    if (!mask->enabled) return;
    if (mask->range_count >= FTFUZZ_MAX_PRESERVE_MASK_RANGES) return;
    ftfuzz_preserve_mask_range_t *r = &mask->ranges[mask->range_count++];
    r->start = start;
    r->end = end;
    r->protection = protection;
    if (role) { strncpy(r->role, role, sizeof(r->role) - 1); r->role[sizeof(r->role) - 1] = 0; }
    if (step_id) { strncpy(r->source_step, step_id, sizeof(r->source_step) - 1); r->source_step[sizeof(r->source_step) - 1] = 0; }
}

static int mask_contains(ftfuzz_preserve_mask_t *mask, size_t pos, uint32_t max_protection) {
    for (size_t i = 0; i < mask->range_count; i++) {
        if (pos >= mask->ranges[i].start && pos < mask->ranges[i].end) {
            if (mask->ranges[i].protection <= max_protection) return 1;
        }
    }
    return 0;
}

static int mask_ratio_ok(ftfuzz_preserve_mask_t *mask, size_t buf_size) {
    uint32_t total = 0;
    for (size_t i = 0; i < mask->range_count; i++)
        total += mask->ranges[i].end - mask->ranges[i].start;
    float ratio = buf_size > 0 ? (float)total / (float)buf_size : 0.0f;
    return ratio <= mask->max_protected_ratio;
}

/* ── Stage 2.7: Queue donor search ── */

static int find_queue_donor(ftfuzz_policy_group_t *pg,
                             unsigned char *donor_buf, size_t *donor_size,
                             size_t max_size, int do_log) {
    if (!pg->donor_rebase.enabled) return 0;
    if (pg->precondition_token_count == 0) return 0;

    const char *qdir = getenv("FTFUZZ_QUEUE_DIR");
    if (!qdir || !qdir[0]) {
        if (do_log) log_msg("[DONOR_MISS] chain=%s reason=no_queue_dir_env\n",
                pg->policy_group_id);
        return 0;
    }

    DIR *d = opendir(qdir);
    if (!d) {
        if (do_log) log_msg("[DONOR_MISS] chain=%s reason=queue_dir_not_openable dir=%s\n",
                pg->policy_group_id, qdir);
        return 0;
    }

    uint32_t scanned = 0;
    uint32_t max_scan = pg->donor_rebase.max_donor_scan;
    if (max_scan == 0) max_scan = (uint32_t)FTFUZZ_MAX_DONOR_SCAN_DEFAULT;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && scanned < max_scan) {
        if (entry->d_name[0] == '.') continue;
        if (strstr(entry->d_name, "id:") != entry->d_name) continue;

        char dpath[1024];
        snprintf(dpath, sizeof(dpath), "%s/%s", qdir, entry->d_name);
        scanned++;

        FILE *fp = fopen(dpath, "rb");
        if (!fp) continue;
        fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
        if (sz <= 0 || (size_t)sz > max_size) { fclose(fp); continue; }
        size_t nread = fread(donor_buf, 1, (size_t)sz, fp);
        fclose(fp);
        if (nread != (size_t)sz) continue;

        const char *token_ptrs[FTFUZZ_MAX_PRECONDITION_TOKENS];
        for (size_t i = 0; i < pg->precondition_token_count; i++)
            token_ptrs[i] = pg->precondition_tokens[i];

        if (check_precondition_tokens(donor_buf, (size_t)sz,
                                       token_ptrs, pg->precondition_token_count,
                                       pg->precondition_token_len)) {
            *donor_size = (size_t)sz;
            g_donor_seeds_scanned_total += scanned;
            closedir(d);
            if (do_log) log_msg("[DONOR_SELECT] chain=%s donor=%s score=1.00 "
                    "anchors=%zu/%zu scanned=%u\n",
                    pg->policy_group_id, entry->d_name,
                    pg->precondition_token_count, pg->precondition_token_count, scanned);
            return 1;
        }
    }

    g_donor_seeds_scanned_total += scanned;
    closedir(d);
    if (do_log) log_msg("[DONOR_MISS] chain=%s reason=no_seed_satisfies_required_tokens "
            "scanned=%u\n", pg->policy_group_id, scanned);
    return 0;
}

/* Execute action chain with IF_PRECONDITION_ELSE_SCAFFOLD + Donor Rebase (Stage 2.7) */
static int exec_action_chain(ftfuzz_policy_group_t *pg,
                              unsigned char *buf, size_t *p_ns,
                              unsigned char **out_buf, size_t max_size,
                              int do_log, ftfuzz_preserve_mask_t *mask) {
    size_t ns = *p_ns;
    unsigned int gen_counter = (unsigned int)(ns * 31 + pg->desired_outcome * 17);
    int did = 0;
    const char *base_source = "none";
    size_t base_offset_before = ns;

    /* Safe buffer for size-changing operations:
       AFL's out_buf is allocated to seed_len, NOT max_size.
       In-place INSERT/DELETE would overflow → heap corruption.
       We allocate a safe buffer at max_size and use it for grow/shrink ops. */
    unsigned char *work_buf = buf;
    int use_safe_buf = 0;

    /* Determine precondition tokens: policy-provided or legacy fallback */
    const char *token_ptrs[FTFUZZ_MAX_PRECONDITION_TOKENS];
    size_t n_tokens;
    if (pg->precondition_token_count > 0) {
        for (size_t i = 0; i < pg->precondition_token_count; i++)
            token_ptrs[i] = pg->precondition_tokens[i];
        n_tokens = pg->precondition_token_count;
    } else {
        token_ptrs[0] = "<!DOCTYPE"; token_ptrs[1] = "["; token_ptrs[2] = "]";
        n_tokens = 3;
    }

    /* ── Tier 1: Current seed precheck ── */
    g_chain_precheck_attempts++;
    g_chain_current_attempts++;
    const int *precond_lens = (pg->precondition_token_count > 0) ? pg->precondition_token_len : NULL;
    /* PaST-Prefix ablation: skip precondition token check, always treat as satisfied */
    int precond_ok = g_ablation_is_prefix ? 1
        : check_precondition_tokens(buf, ns, token_ptrs, n_tokens, precond_lens);

    if (do_log) {
        log_msg("[CHAIN_PRECHECK] chain=%s seed_len=%zu satisfied=%s\n",
                pg->policy_group_id, ns, precond_ok ? "true" : "false");
    }

    /* Force reload if precond fails and scaffold is empty — the policy
       may have been updated by the daemon since we last loaded it. */
    if (!precond_ok && pg->scaffold_template_len == 0) {
        if (ftfuzz_policy_loader_reload_if_needed()) {
            ftfuzz_policy_loader_get_store(&g_store);
            g_reloads++;
            g_cached_has_pol = -1;
            g_scaffold_rebuild_success = 0;   /* reset: new policy may have new scaffold */
            g_scaffold_skeleton_valid = 0;
            log_msg("[RELOAD] v%lu (triggered by precond_fail) groups=%zu\n",
                    (unsigned long)g_store.store_version,
                    g_store.policy_group_count);
            /* Re-fetch the policy group after reload */
            ftfuzz_policy_group_t *fresh_pg = NULL;
            for (size_t i = 0; i < g_store.policy_group_count; i++) {
                if (!strcmp(g_store.policy_groups[i].policy_group_id, pg->policy_group_id)) {
                    fresh_pg = &g_store.policy_groups[i];
                    break;
                }
            }
            if (fresh_pg && fresh_pg->scaffold_template_len > 0) {
                *pg = *fresh_pg;  /* use updated group with scaffold */
                precond_lens = (pg->precondition_token_count > 0) ? pg->precondition_token_len : NULL;
                if (do_log) log_msg("[RELOAD_RETRY] chain=%s scaffold_len=%d\n",
                        pg->policy_group_id, pg->scaffold_template_len);
            }
        }
    }

    if (precond_ok) {
        g_chain_precondition_pass++;
        g_chain_current_success++;
        base_source = "current_seed";
    }

    /* ── Tier 1.5: Force scaffold when in-place chain is stuck ──
       Triggers when: (a) chain has succeeded many times without scaffold proving
       itself, OR (b) chain has failed many times consecutively across seeds. */
    int chain_stuck = (precond_ok && pg->scaffold_template_len > 0 &&
        g_chain_current_success > 0 &&
        (g_chain_current_success % 50) == 0 &&
        g_scaffold_rebuild_success == 0);
    int chain_failing = (precond_ok && pg->scaffold_template_len > 0 &&
        g_chain_consecutive_failures > 0 &&
        (g_chain_consecutive_failures % 200) == 0);
    if (chain_stuck || chain_failing) {
        if (do_log) log_msg("[CHAIN_STUCK] chain=%s reason=%s chain_current=%lu failures=%llu — forcing scaffold\n",
                pg->policy_group_id,
                chain_failing ? "consecutive_failures" : "no_scaffold_progress",
                (unsigned long)g_chain_current_success,
                (unsigned long long)g_chain_consecutive_failures);
        precond_ok = 0;
    }

    /* ── Tier 2: Scaffold instantiation when precond fails ──
       When current seed doesn't have precondition tokens, instantiate
       the LLM's scaffold_template directly.  To avoid the deterministic-
       output loop (every seed triggers scaffold → same output → AFL
       rejects → next seed triggers scaffold again), rebuild ONLY once.
       After the first success, non-scaffold seeds skip the chain entirely;
       only seeds that already carry the scaffold skeleton get in-place
       chain execution. */
    if (!precond_ok && pg->scaffold_template_len > 0) {
        if (g_scaffold_rebuild_success > 0) {
            /* Scaffold has already succeeded before.  Check if this seed
             * is a scaffold product — if so, allow in-place chain to
             * potentially produce a variant.  Otherwise skip. */
            uint32_t cur_hash = compute_skeleton_hash(buf, ns);
            if (cur_hash == g_scaffold_skeleton_hash) {
                precond_ok = 1;
                base_source = "scaffold_seed";
                base_offset_before = 0;
                if (do_log) log_msg("[SCAFFOLD_INPLACE] chain=%s seed matches scaffold skeleton — "
                        "allowing in-place chain\n", pg->policy_group_id);
            } else {
                g_chain_ineligible++;
                if (do_log && (g_calls < 10 || g_chain_ineligible % 100 == 0))
                    log_msg("[SCAFFOLD_SKIP] chain=%s reason=already_succeeded "
                            "seed_hash=%08x scaffold_hash=%08x\n",
                            pg->policy_group_id, cur_hash, g_scaffold_skeleton_hash);
                return 0;  /* skip chain; let AFL native havoc handle this seed */
            }
        } else {
            /* First scaffold attempt (or previous attempts all failed) */
            g_scaffold_rebuild_attempts++;
            if (do_log) log_msg("[SCAFFOLD_REBUILD] chain=%s old_len=%zu "
                    "reason=precond_failed_scaffold_first source=llm_scaffold\n",
                    pg->policy_group_id, ns);

            if (instantiate_scaffold(buf, &ns, max_size, pg->scaffold_template,
                                      pg->scaffold_template_len,
                                      &gen_counter, do_log, pg->policy_group_id)) {
                g_scaffold_rebuild_success++;
                check_scaffold_retry_threshold(pg->policy_group_id);
                precond_ok = 1;
                base_source = "llm_scaffold";
                base_offset_before = 0;
                *p_ns = ns;
                did = 0;  /* allow bytecode ops to execute on scaffold output */
                g_scaffold_skeleton_hash = compute_skeleton_hash(buf, ns);
                g_scaffold_skeleton_valid = 1;
                if (do_log) log_msg("[CHAIN_EXEC] chain=%s base_source=%s "
                        "result=success new_len=%zu\n",
                        pg->policy_group_id, base_source, ns);
            } else {
                g_scaffold_rebuild_rejected++;
                g_chain_ineligible++;
                g_chain_no_base_skip++;
            }
        }
    }

    /* ── Tier 3: Queue donor search (only if no scaffold or scaffold failed) ── */
    static unsigned char *g_donor_buf = NULL;
    static size_t g_donor_buf_size = 0;
    size_t donor_size = 0;

    if (!precond_ok && pg->donor_rebase.enabled) {
        g_chain_donor_attempts++;
        if (!g_donor_buf || g_donor_buf_size < max_size) {
            free(g_donor_buf);
            g_donor_buf = malloc(max_size);
            g_donor_buf_size = g_donor_buf ? max_size : 0;
        }
        if (g_donor_buf && find_queue_donor(pg, g_donor_buf, &donor_size, max_size, do_log)) {
            g_chain_donor_success++;
            precond_ok = 1;
            base_source = "queue_donor";
            memcpy(buf, g_donor_buf, donor_size);
            ns = donor_size;
            base_offset_before = ns;
            gen_counter = (unsigned int)(ns * 31 + pg->desired_outcome * 17);
        } else {
            g_chain_donor_miss++;
        }
    }

    /* ── Tier 3.5: Generic token patch (binary/scaffold-free) ──
       When dictionary tokens exist but XML chain ops don't apply (binary formats),
       find the last anchor token in the buffer and insert dictionary values there. */
    if (!did && pg->dictionary_token_count > 0) {
        const char *last_anchor = NULL;
        const char *anchor_for_patch[FTFUZZ_MAX_TOKEN_LEN] = {0};
        int anchor_for_patch_len = 0;

        /* Use the last precondition token as anchor, or first dictionary token */
        if (pg->precondition_token_count > 0) {
            last_anchor = pg->precondition_tokens[pg->precondition_token_count - 1];
        } else if (pg->dictionary_token_count > 0) {
            /* Use first dict token to find insertion point */
            last_anchor = pg->dictionary_tokens[0].token;
        }

        if (last_anchor) {
            int alen = pg->precondition_token_count > 0 ? pg->precondition_token_len[pg->precondition_token_count - 1] : (int)strlen(last_anchor);
            /* Search buffer for anchor bytes */
            for (size_t i = 0; i + (size_t)alen <= ns; i++) {
                if (!memcmp(buf + i, last_anchor, (size_t)alen)) {
                    /* Found anchor — insert dictionary tokens right after it */
                    size_t insert_pos = i + (size_t)alen;
                    size_t total_insert = 0;
                    for (size_t di = 0; di < pg->dictionary_token_count; di++) {
                        const char *tok = pg->dictionary_tokens[di].token;
                        int dlen = pg->dictionary_tokens[di].token_len;
                        if (dlen <= 0) dlen = (int)strlen(tok);
                        if (insert_pos + total_insert + dlen <= max_size) {
                            /* Shift remaining data right */
                            if (insert_pos + total_insert < ns) {
                                memmove(buf + insert_pos + total_insert + dlen,
                                        buf + insert_pos + total_insert,
                                        ns - (insert_pos + total_insert));
                            }
                            memcpy(buf + insert_pos + total_insert, tok, dlen);
                            total_insert += dlen;
                        }
                    }
                    if (total_insert > 0) {
                        ns += total_insert;
                        *p_ns = ns;
                        did = 1;
                        base_source = "generic_patch";
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[GENERIC_PATCH] chain=%s anchor=%s "
                                "at_offset=%zu inserted=%zu bytes new_len=%zu\n",
                                pg->policy_group_id, last_anchor, i, total_insert, ns);
                    }
                    break;
                }
            }
        }
    }


    /* ── Layer 1: Quick pre-filter for critical FIND patterns ──
     * Before expensive pre-resolve + step execution, check whether
     * this seed contains the FIND patterns needed by active ops
     * (WRITE/INSERT/DELETE/SET_INT/INC_INT/SIZE_TO).  If a critical
     * pattern is missing, skip the chain immediately — the ops that
     * depend on it cannot succeed anyway. */
    if (precond_ok && !did && pg->action_step_count > 0) {
        /* Collect FIND output names referenced by active ops */
        char critical_refs[FTFUZZ_MAX_FIND_REFS][32];
        int critical_count = 0;
        for (size_t si = 0; si < pg->action_step_count; si++) {
            ftfuzz_action_step_t *st = &pg->action_steps[si];
            if (strcmp(st->op, "WRITE") && strcmp(st->op, "INSERT") &&
                strcmp(st->op, "DELETE") && strcmp(st->op, "SET_INT") &&
                strcmp(st->op, "INC_INT") && strcmp(st->op, "SIZE_TO"))
                continue;
            /* Extract {ref} name from offset/field_offset param */
            for (int pi = 0; pi < st->param_count; pi++) {
                const char *k = st->param_keys[pi];
                const char *v = st->param_values[pi];
                if (!k || !v) continue;
                if (strcmp(k, "offset") && strcmp(k, "field_offset") &&
                    strcmp(k, "range_start") && strcmp(k, "range_end"))
                    continue;
                if (v[0] == '{') {
                    const char *close = strchr(v, '}');
                    if (close) {
                        size_t nl = (size_t)(close - v - 1);
                        if (nl > 0 && nl < 32 && critical_count < FTFUZZ_MAX_FIND_REFS) {
                            int dup = 0;
                            for (int ci = 0; ci < critical_count; ci++)
                                if (!strncmp(critical_refs[ci], v + 1, nl) && critical_refs[ci][nl] == 0)
                                    { dup = 1; break; }
                            if (!dup) {
                                memcpy(critical_refs[critical_count], v + 1, nl);
                                critical_refs[critical_count][nl] = 0;
                                critical_count++;
                            }
                        }
                    }
                }
            }
        }
        /* Quick-scan: for each critical FIND, check if pattern exists */
        if (critical_count > 0) {
            for (int ci = 0; ci < critical_count; ci++) {
                /* Locate the FIND step for this ref */
                const char *phex = NULL;
                for (size_t si = 0; si < pg->action_step_count; si++) {
                    ftfuzz_action_step_t *st = &pg->action_steps[si];
                    if (strcmp(st->op, "FIND")) continue;
                    const char *out = NULL;
                    for (int pi = 0; pi < st->param_count; pi++) {
                        if (!strcmp(st->param_keys[pi], "output")) out = st->param_values[pi];
                        if (!strcmp(st->param_keys[pi], "pattern")) phex = st->param_values[pi];
                    }
                    if (out && phex && !strcmp(out, critical_refs[ci])) break;
                    phex = NULL;
                }
                if (!phex) continue;
                unsigned char pat[256];
                size_t plen = decode_data(phex, pat, sizeof(pat));
                if (plen == 0) continue;
                /* Search buffer for pattern */
                int found = 0;
                for (size_t i = 0; i + plen <= ns; i++) {
                    if (!memcmp(work_buf + i, pat, plen)) { found = 1; break; }
                }
                if (!found) {
                    if (do_log) log_msg("[CHAIN_SKIP] chain=%s reason=find_missing ref=%s\n",
                            pg->policy_group_id, critical_refs[ci]);
                    g_chain_consecutive_failures++;
                    return 0;
                }
            }
        }
    }

    /* ── Bytecode Plan: Pre-resolve all FIND operations ──
     * Run BEFORE the main step loop so that subsequent steps can
     * reference the resolved offsets via {ref_name}. */
    if (precond_ok && !did && pg->action_step_count > 0) {
        pg->find_ref_count = 0;
        for (size_t si = 0; si < pg->action_step_count; si++) {
            ftfuzz_action_step_t *step = &pg->action_steps[si];
            if (strcmp(step->op, "FIND")) continue;
            if (pg->find_ref_count >= FTFUZZ_MAX_FIND_REFS) break;

            /* Get pattern */
            const char *pattern_hex = NULL;
            for (int pi = 0; pi < step->param_count; pi++) {
                if (!strcmp(step->param_keys[pi], "pattern"))
                    pattern_hex = step->param_values[pi];
            }
            if (!pattern_hex) continue;

            /* Decode pattern */
            unsigned char pattern[256];
            size_t plen = decode_data(pattern_hex, pattern, sizeof(pattern));
            if (plen == 0) continue;

            /* Get start offset */
            uint32_t search_start = 0;
            for (int pi = 0; pi < step->param_count; pi++) {
                if (!strcmp(step->param_keys[pi], "start")) {
                    uint32_t tmp;
                    if (resolve_offset(step->param_values[pi], pg, ns, &tmp) == 0)
                        search_start = tmp;
                }
            }

            /* Get occurrence */
            int occur = 1;
            for (int pi = 0; pi < step->param_count; pi++) {
                if (!strcmp(step->param_keys[pi], "occurrence"))
                    occur = atoi(step->param_values[pi]);
            }
            if (occur < 1) occur = 1;

            /* Search in buffer */
            int found = 0;
            uint32_t match_offset = 0;
            int occ_count = 0;
            for (size_t i = search_start; i + plen <= ns; i++) {
                if (!memcmp(work_buf + i, pattern, plen)) {
                    occ_count++;
                    if (occ_count == occur) {
                        match_offset = (uint32_t)i;
                        found = 1;
                        break;
                    }
                }
            }

            /* Get output name */
            const char *out_name = NULL;
            for (int pi = 0; pi < step->param_count; pi++) {
                if (!strcmp(step->param_keys[pi], "output"))
                    out_name = step->param_values[pi];
            }
            if (!out_name) out_name = "unnamed";

            /* Store result */
            int ri = pg->find_ref_count++;
            strncpy(pg->find_refs[ri].name, out_name, 31);
            pg->find_refs[ri].name[31] = '\0';
            pg->find_refs[ri].offset = match_offset;
            pg->find_refs[ri].found = found;

            if (do_log) {
                log_msg("[FIND] chain=%s step=%d pattern=%zu_bytes output=%s "
                        "found=%d offset=%u start=%u occur=%d\n",
                        pg->policy_group_id, step->step, plen, out_name,
                        found, match_offset, search_start, occur);
            }
        }
    }

    /* ── Tier 3.8: Generic action step execution (Stage 2.8) ──
       Iterate through Compiler-generated action_steps and execute each op.
       Format-agnostic: uses precondition tokens as anchors, dictionary tokens
       as payload. Active ops (ENSURE_REGION_EXISTS, INSERT_*) modify the seed;
       passive ops (PRESERVE_*) add preserve mask ranges.

       CRITICAL: AFL's out_buf is allocated to the seed's current length,
       NOT to max_size. In-place INSERT/DELETE operations that grow the seed
       beyond the original len will overflow the buffer and corrupt the heap.
       Detect size-changing ops and switch to a safe buffer (g_insert_buf)
       allocated to max_size before executing any step. */
    if (precond_ok && !did && pg->action_step_count > 0) {
        size_t region_pos = ns;    /* fallback: append at end */
        size_t region_len = 0;
        int region_found = 0;

        /* ── Safe buffer for size-changing bytecode ops ── */
        {
            int has_grow = 0;
            for (size_t si = 0; si < pg->action_step_count; si++) {
                const char *op = pg->action_steps[si].op;
                if (!strcmp(op, "INSERT") || !strcmp(op, "DELETE") ||
                    !strcmp(op, "INSERT_DECLARATION_FIELD_OR_SNIPPET") ||
                    !strcmp(op, "INSERT_MATCHING_FIELD_INSTANCE") ||
                    !strcmp(op, "ENSURE_REGION_EXISTS") ||
                    !strcmp(op, "INSERT_REFERENCE_INSTANCE")) {
                    has_grow = 1; break;
                }
            }
            if (has_grow) {
                if (!g_insert_buf || g_insert_buf_size < max_size) {
                    free(g_insert_buf);
                    g_insert_buf = malloc(max_size);
                    g_insert_buf_size = g_insert_buf ? max_size : 0;
                }
                if (g_insert_buf) {
                    memcpy(g_insert_buf, buf, ns);
                    work_buf = g_insert_buf;
                    use_safe_buf = 1;
                    if (do_log) log_msg("[SAFE_BUF] chain=%s switched to safe buffer "
                            "max_size=%zu seed_len=%zu\n",
                            pg->policy_group_id, max_size, ns);
                }
            }
        }

        for (size_t si = 0; si < pg->action_step_count; si++) {
            ftfuzz_action_step_t *step = &pg->action_steps[si];
            if (do_log) {
                log_msg("[STEP_EXEC] chain=%s step=%d op=%s region=%s params=%d\n",
                        pg->policy_group_id, step->step, step->op,
                        step->region_role, step->param_count);
            }

            /* ── Active ops: find region, insert data ── */
            if (!strcmp(step->op, "ENSURE_REGION_EXISTS") ||
                !strcmp(step->op, "INSERT_DECLARATION_FIELD_OR_SNIPPET")) {
                /* Find region by searching for the last precondition token
                   as an anchor for the target region. */
                if (!region_found && pg->precondition_token_count > 0) {
                    const char *anchor = pg->precondition_tokens[pg->precondition_token_count - 1];
                    int alen = pg->precondition_token_len[pg->precondition_token_count - 1];
                    if (alen <= 0) alen = (int)strlen(anchor);
                    for (size_t i = 0; i + (size_t)alen <= ns; i++) {
                        if (!memcmp(work_buf + i, anchor, (size_t)alen)) {
                            region_pos = i + (size_t)alen;
                            region_len = 0;
                            region_found = 1;
                            break;
                        }
                    }
                }
                if (!region_found && pg->dictionary_token_count > 0) {
                    /* Fallback: use first dict token as anchor */
                    const char *anchor = pg->dictionary_tokens[0].token;
                    int alen = pg->dictionary_tokens[0].token_len;
                    if (alen <= 0) alen = (int)strlen(anchor);
                    for (size_t i = 0; i + (size_t)alen <= ns; i++) {
                        if (!memcmp(work_buf + i, anchor, (size_t)alen)) {
                            region_pos = i;
                            region_len = alen;
                            region_found = 1;
                            break;
                        }
                    }
                }
                if (do_log) {
                    log_msg("[STEP_REGION] chain=%s op=%s found=%d pos=%zu\n",
                            pg->policy_group_id, step->op, region_found, region_pos);
                }
            }

            if (!strcmp(step->op, "INSERT_DECLARATION_FIELD_OR_SNIPPET") ||
                !strcmp(step->op, "INSERT_MATCHING_FIELD_INSTANCE")) {
                /* Insert dictionary tokens at region position */
                size_t total_insert = 0;
                for (size_t di = 0; di < pg->dictionary_token_count; di++) {
                    const char *tok = pg->dictionary_tokens[di].token;
                    int dlen = pg->dictionary_tokens[di].token_len;
                    if (dlen <= 0) dlen = (int)strlen(tok);
                    size_t insert_at = region_pos + total_insert;
                    if (insert_at + dlen <= max_size) {
                        if (insert_at < ns) {
                            memmove(work_buf + insert_at + dlen, work_buf + insert_at, ns - insert_at);
                        }
                        memcpy(work_buf + insert_at, tok, dlen);
                        total_insert += dlen;
                    }
                }
                if (total_insert > 0) {
                    ns += total_insert;
                    *p_ns = ns; did = 1;
                    g_chain_inplace_success++;
                    if (do_log) {
                        log_msg("[STEP_INSERT] chain=%s step=%d op=%s inserted=%zu bytes\n",
                                pg->policy_group_id, step->step, step->op, total_insert);
                    }
                }
                if (step->requires_success && total_insert == 0) {
                    if (do_log) log_msg("[STEP_FAIL] chain=%s step=%d op=%s requires_success, aborting\n",
                            pg->policy_group_id, step->step, step->op);
                    break;
                }
            }

            /* ── Bytecode Plan ops: format-agnostic buffer operations ── */

            /* WRITE: overwrite bytes at offset without changing buffer size */
            if (!strcmp(step->op, "WRITE")) {
                const char *offset_str = NULL, *data_hex = NULL;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "offset")) offset_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "data")) data_hex = step->param_values[pi];
                }
                uint32_t abs_off;
                if (offset_str && data_hex &&
                    resolve_offset(offset_str, pg, ns, &abs_off) == 0) {
                    unsigned char wbuf[256];
                    size_t wlen = decode_data(data_hex, wbuf, sizeof(wbuf));
                    if (wlen > 0 && abs_off + wlen <= ns) {
                        memcpy(work_buf + abs_off, wbuf, wlen);
                        did = 1;
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[WRITE] chain=%s step=%d offset=%u len=%zu\n",
                                pg->policy_group_id, step->step, abs_off, wlen);
                    }
                }
            }

            /* INSERT: insert bytes at offset, shifting rest right */
            if (!strcmp(step->op, "INSERT")) {
                const char *offset_str = NULL, *data_hex = NULL;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "offset")) offset_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "data")) data_hex = step->param_values[pi];
                }
                uint32_t abs_off;
                if (offset_str && data_hex &&
                    resolve_offset(offset_str, pg, ns, &abs_off) == 0) {
                    unsigned char ibuf[256];
                    size_t ilen = decode_data(data_hex, ibuf, sizeof(ibuf));
                    if (ilen > 0 && ns + ilen <= max_size && abs_off <= ns) {
                        if (abs_off < ns)
                            memmove(work_buf + abs_off + ilen, work_buf + abs_off, ns - abs_off);
                        memcpy(work_buf + abs_off, ibuf, ilen);
                        ns += ilen;
                        *p_ns = ns; did = 1;
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[INSERT] chain=%s step=%d offset=%u len=%zu new_ns=%zu\n",
                                pg->policy_group_id, step->step, abs_off, ilen, ns);
                    }
                }
            }

            /* DELETE: remove byte range, shifting rest left */
            if (!strcmp(step->op, "DELETE")) {
                const char *offset_str = NULL;
                int del_len = 0;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "offset")) offset_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "length")) del_len = atoi(step->param_values[pi]);
                }
                uint32_t abs_off;
                if (offset_str && del_len > 0 &&
                    resolve_offset(offset_str, pg, ns, &abs_off) == 0) {
                    if (abs_off + (size_t)del_len <= ns) {
                        memmove(work_buf + abs_off, work_buf + abs_off + del_len,
                                ns - abs_off - del_len);
                        ns -= del_len;
                        *p_ns = ns; did = 1;
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[DELETE] chain=%s step=%d offset=%u len=%d new_ns=%zu\n",
                                pg->policy_group_id, step->step, abs_off, del_len, ns);
                    }
                }
            }

            /* SET_INT: write integer at offset */
            if (!strcmp(step->op, "SET_INT")) {
                const char *offset_str = NULL, *endian = "le";
                int width = 4, value = 0;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "offset")) offset_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "width")) width = atoi(step->param_values[pi]);
                    if (!strcmp(step->param_keys[pi], "endian")) endian = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "value")) value = atoi(step->param_values[pi]);
                }
                uint32_t abs_off;
                if (offset_str && width >= 1 && width <= 8 &&
                    resolve_offset(offset_str, pg, ns, &abs_off) == 0) {
                    if (abs_off + (size_t)width <= ns) {
                        write_integer(work_buf, abs_off, width, endian, (uint64_t)(int64_t)value);
                        did = 1;
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[SET_INT] chain=%s step=%d offset=%u width=%d "
                                "endian=%s value=%d\n",
                                pg->policy_group_id, step->step, abs_off, width, endian, value);
                    }
                }
            }

            /* INC_INT: read integer, add delta, write back */
            if (!strcmp(step->op, "INC_INT")) {
                const char *offset_str = NULL, *endian = "le";
                int width = 4, delta = 0;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "offset")) offset_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "width")) width = atoi(step->param_values[pi]);
                    if (!strcmp(step->param_keys[pi], "endian")) endian = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "delta")) delta = atoi(step->param_values[pi]);
                }
                uint32_t abs_off;
                if (offset_str && width >= 1 && width <= 8 &&
                    resolve_offset(offset_str, pg, ns, &abs_off) == 0) {
                    if (abs_off + (size_t)width <= ns) {
                        uint64_t cur = read_integer(work_buf, abs_off, width, endian);
                        uint64_t new_val = (uint64_t)((int64_t)cur + delta);
                        write_integer(work_buf, abs_off, width, endian, new_val);
                        did = 1;
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[INC_INT] chain=%s step=%d offset=%u width=%d "
                                "endian=%s delta=%d old=%llu new=%llu\n",
                                pg->policy_group_id, step->step, abs_off, width,
                                endian, delta, (unsigned long long)cur, (unsigned long long)new_val);
                    }
                }
            }

            /* SIZE_TO: set integer to byte-length between two named refs */
            if (!strcmp(step->op, "SIZE_TO")) {
                const char *field_off_str = NULL, *endian = "le";
                const char *range_start_str = NULL, *range_end_str = NULL;
                int width = 4;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "field_offset")) field_off_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "width")) width = atoi(step->param_values[pi]);
                    if (!strcmp(step->param_keys[pi], "endian")) endian = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "range_start")) range_start_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "range_end")) range_end_str = step->param_values[pi];
                }
                uint32_t field_off, rs_off, re_off;
                if (field_off_str && range_start_str && range_end_str && width >= 1 && width <= 8 &&
                    resolve_offset(field_off_str, pg, ns, &field_off) == 0 &&
                    resolve_offset(range_start_str, pg, ns, &rs_off) == 0 &&
                    resolve_offset(range_end_str, pg, ns, &re_off) == 0) {
                    if (re_off >= rs_off && field_off + (size_t)width <= ns) {
                        uint64_t range_len = re_off - rs_off;
                        write_integer(work_buf, field_off, width, endian, range_len);
                        did = 1;
                        g_chain_inplace_success++;
                        if (do_log) log_msg("[SIZE_TO] chain=%s step=%d field_off=%u width=%d "
                                "endian=%s range=%u-%u len=%llu\n",
                                pg->policy_group_id, step->step, field_off, width, endian,
                                rs_off, re_off, (unsigned long long)range_len);
                    }
                }
            }

            /* PRESERVE (bytecode): protect range from havoc */
            if (!strcmp(step->op, "PRESERVE")) {
                const char *offset_str = NULL;
                int plen = 0;
                for (int pi = 0; pi < step->param_count; pi++) {
                    if (!strcmp(step->param_keys[pi], "offset")) offset_str = step->param_values[pi];
                    if (!strcmp(step->param_keys[pi], "length")) plen = atoi(step->param_values[pi]);
                }
                uint32_t abs_off;
                if (offset_str && plen > 0 &&
                    resolve_offset(offset_str, pg, ns, &abs_off) == 0) {
                    if (mask && mask->enabled) {
                        uint32_t end = abs_off + (uint32_t)plen;
                        if (end > ns) end = (uint32_t)ns;
                        if (end > abs_off) {
                            mask_add_range(mask, abs_off, end, 0, "bytecode", step->action_id);
                            g_preserve_mask_ranges_total++;
                            if (do_log) log_msg("[PRESERVE] chain=%s step=%d range=%u-%u\n",
                                    pg->policy_group_id, step->step, abs_off, end);
                        }
                    }
                    did = 1; /* PRESERVE counts as an effect even without mask */
                }
            }

            /* ── Passive ops: add preserve ranges ── */
            if (!strcmp(step->op, "PRESERVE_BOUND_TOKENS_OR_FIELDS") ||
                !strcmp(step->op, "PRESERVE_BINDING_KEYS") ||
                !strcmp(step->op, "PRESERVE_REGION") ||
                !strcmp(step->op, "PRESERVE_REACHABILITY_REGION")) {
                if (mask && mask->enabled && pg->preserve_mask.protect_inserted_ranges) {
                    uint32_t start = (uint32_t)region_pos;
                    uint32_t end = (uint32_t)(region_pos + region_len);
                    if (end > start) {
                        mask_add_range(mask, start, end, 0, step->region_role, step->action_id);
                        g_preserve_mask_ranges_total++;
                        if (do_log) log_msg("[STEP_PRESERVE] chain=%s step=%d range=%u-%u\n",
                                pg->policy_group_id, step->step, start, end);
                    }
                }
            }
        }
    }

    /* ── Tier 4: Execute in-place chain on base seed ──
       XML-specific operations (ATTLIST declarations, ID attributes) are
       designed for text/XML formats. For binary formats (ELF, JPEG, etc.),
       they corrupt data AND risk infinite loops when XML patterns appear
       coincidentally in binary buffers. Skip and rely on Tier 3.8 generic
       step execution instead. */
    static int g_input_is_binary = -1;
    if (g_input_is_binary < 0) {
        const char *fmt = getenv("FTFUZZ_INPUT_FORMAT");
        g_input_is_binary = (fmt && !strcmp(fmt, "binary")) ? 1 : 0;
    }
    if (precond_ok && !did && !g_input_is_binary) {
        /* Ensure safe buffer for XML grow operations */
        if (!use_safe_buf) {
            if (!g_insert_buf || g_insert_buf_size < max_size) {
                free(g_insert_buf);
                g_insert_buf = malloc(max_size);
                g_insert_buf_size = g_insert_buf ? max_size : 0;
            }
            if (g_insert_buf) {
                memcpy(g_insert_buf, work_buf, ns);
                work_buf = g_insert_buf;
                use_safe_buf = 1;
                if (do_log) log_msg("[SAFE_BUF] chain=%s Tier4 XML switched to safe buffer\n",
                        pg->policy_group_id);
            }
        }
        g_chain_inplace_attempts++;
        /* Use policy-agnostic chain steps: insert declaration + matching instance */
        const char *elem = "child1";
        const char *attr = "id";
        const char *atype = "ID";

        if (chain_insert_attlist_decl(work_buf, &ns, max_size, elem, attr, atype)) {
            if (do_log) log_msg("[PLAN_STEP] group=%s step=1 op=INSERT_DECLARATION_FIELD_OR_SNIPPET "
                    "result=success\n", pg->policy_group_id);

            /* Track inserted declaration range in preserve mask */
            if (mask && mask->enabled && pg->preserve_mask.protect_inserted_ranges) {
                /* ATTLIST inserted at DTD internal subset end; approximate range */
                size_t decl_pos = 0;
                for (size_t i = 0; i + 9 < ns; i++) {
                    if (!memcmp(work_buf + i, "<!ATTLIST", 9)) {
                        decl_pos = i;
                        for (size_t j = i; j < ns; j++) {
                            if (work_buf[j] == '\n') {
                                mask_add_range(mask, (uint32_t)decl_pos, (uint32_t)(j + 1),
                                              0 /* no_havoc */,
                                              "declaration_snippet", "STEP_1");
                                break;
                            }
                        }
                        if (mask->range_count > 0) {
                            g_preserve_mask_ranges_total++;
                            g_protected_bytes_total += mask->ranges[mask->range_count - 1].end
                                                     - mask->ranges[mask->range_count - 1].start;
                        }
                        break;
                    }
                }
            }

            char id_value[64];
            dsl_gen_identifier(id_value, sizeof(id_value), "ftid", &gen_counter);
            if (chain_insert_matching_field(work_buf, &ns, max_size, elem, attr, id_value)) {
                if (do_log) log_msg("[PLAN_STEP] group=%s step=2 op=INSERT_MATCHING_FIELD_INSTANCE "
                        "value=%s result=success\n", pg->policy_group_id, id_value);

                /* Track inserted instance field in preserve mask */
                if (mask && mask->enabled && pg->preserve_mask.protect_inserted_ranges) {
                    /* Find the id="..." we just inserted */
                    char id_search[128];
                    snprintf(id_search, sizeof(id_search), "id=\"%s\"", id_value);
                    for (size_t i = 0; i + strlen(id_search) <= ns; i++) {
                        if (!memcmp(work_buf + i, id_search, strlen(id_search))) {
                            mask_add_range(mask, (uint32_t)i,
                                          (uint32_t)(i + strlen(id_search)),
                                          0 /* no_havoc */,
                                          "matching_instance_field", "STEP_2");
                            g_preserve_mask_ranges_total++;
                            g_protected_bytes_total += (uint32_t)strlen(id_search);
                            break;
                        }
                    }
                }

                g_chain_inplace_success++;
                *p_ns = ns; did = 1;
                if (do_log) log_msg("[CHAIN_EXEC] chain=%s base_source=%s result=success "
                        "new_len=%zu\n", pg->policy_group_id, base_source, ns);
            }
        } else {
            if (do_log) log_msg("[PLAN_STEP] group=%s step=1 result=fail reason=no_dtd_subset\n",
                    pg->policy_group_id);

            /* ── Tier 3: Scaffold fallback when chain execution fails ── */
            const char *scaffold_tmpl = NULL;
            const char *scaffold_source = "none";

            if (pg->scaffold_template_len > 0) {
                scaffold_tmpl = pg->scaffold_template;
                scaffold_source = "llm_scaffold";
            }

            if (scaffold_tmpl) {
                g_scaffold_rebuild_attempts++;
                if (do_log) log_msg("[SCAFFOLD_REBUILD] chain=%s old_len=%zu "
                        "reason=chain_step_failed source=%s\n",
                        pg->policy_group_id, ns, scaffold_source);

                if (instantiate_scaffold(work_buf, &ns, max_size, scaffold_tmpl,
                                          pg->scaffold_template_len,
                                          &gen_counter, do_log, pg->policy_group_id)) {
                    g_scaffold_rebuild_success++;
                    check_scaffold_retry_threshold(pg->policy_group_id);
                    *p_ns = ns; did = 1;
                    base_source = scaffold_source;

                    g_scaffold_skeleton_hash = compute_skeleton_hash(work_buf, ns);
                    g_scaffold_skeleton_valid = 1;

                    if (mask && mask->enabled && pg->preserve_mask.protect_inserted_ranges) {
                        mask_add_range(mask, 0, (uint32_t)ns,
                                      0 /* no_havoc */,
                                      "scaffold_skeleton", "SCAFFOLD");
                        g_preserve_mask_ranges_total++;
                        g_protected_bytes_total += (uint32_t)ns;
                    }

                    if (do_log) log_msg("[CHAIN_EXEC] chain=%s base_source=%s "
                            "result=success new_len=%zu\n",
                            pg->policy_group_id, base_source, ns);
                } else {
                    g_scaffold_rebuild_rejected++;
                    g_chain_ineligible++;
                    g_chain_no_base_skip++;
                }
            } else {
                g_chain_no_base_skip++;
                g_chain_consecutive_failures++;
                if (do_log) log_msg("[CHAIN_NO_BASE] chain=%s reason=no_scaffold_template "
                        "chain_failed=true\n", pg->policy_group_id);
            }
        }
    } else {
        g_chain_precondition_fail++;
        g_chain_no_base_skip++;
        g_chain_consecutive_failures++;
        if (do_log) log_msg("[CHAIN_NO_BASE] chain=%s reason=all_tiers_failed\n",
                pg->policy_group_id);
    }

    if (did) {
        /* If we used the safe buffer (g_insert_buf), hand ownership to AFL.
           AFL will free() it via DFL_ck_free. Otherwise, use the original buf. */
        if (use_safe_buf && g_insert_buf) {
            *out_buf = g_insert_buf;
            /* Reuse buffer next call — AFL copies data synchronously, so it
               won't access this buffer after common_fuzz_stuff() returns. */
            if (do_log) log_msg("[SAFE_BUF_HANDOFF] chain=%s final_len=%zu\n",
                    pg->policy_group_id, ns);
        } else {
            *out_buf = buf;
        }
        if (mask && mask->enabled && mask->range_count > 0) {
            g_preserve_mask_created++;
            if (!mask_ratio_ok(mask, ns)) {
                g_mask_limit_triggered++;
                if (do_log) log_msg("[MASK_LIMIT] chain=%s protected_ratio=%.2f max=%.2f "
                        "action=truncate_low_confidence_ranges\n",
                        pg->policy_group_id,
                        mask->max_protected_ratio > 0.0f ?
                            (float)g_protected_bytes_total / (float)ns : 0.0f,
                        mask->max_protected_ratio);
            }
            if (do_log) log_msg("[MASK_CREATE] chain=%s ranges=%zu bytes=%u ratio=%.2f\n",
                    pg->policy_group_id, mask->range_count,
                    (unsigned)(base_source[0] ? (uint32_t)(ns - base_offset_before + g_protected_bytes_total - g_protected_bytes_total)
                               : (uint32_t)g_protected_bytes_total),
                    (float)(mask->range_count > 0 ? (float)g_protected_bytes_total / (float)ns : 0.0f));
            for (size_t mi = 0; mi < mask->range_count; mi++) {
                if (do_log) log_msg("[MASK_RANGE] chain=%s step=%s role=%s start=%u end=%u protection=%u\n",
                        pg->policy_group_id, mask->ranges[mi].source_step,
                        mask->ranges[mi].role, mask->ranges[mi].start,
                        mask->ranges[mi].end, mask->ranges[mi].protection);
            }
        }
    }


    if (!did && base_source && !strcmp(base_source, "scaffold_seed")) {
        g_scaffold_inplace_failures++;
        if (do_log && (g_scaffold_inplace_failures % 10 == 0))
            log_msg("[SCAFFOLD_INPLACE_FAIL] chain=%s failures=%llu\\n",
                    pg->policy_group_id,
                    (unsigned long long)g_scaffold_inplace_failures);
        if (g_scaffold_inplace_failures >= 50) {
            if (do_log)
                log_msg("[SCAFFOLD_INPLACE_EXHAUST] chain=%s failures=%llu\\n",
                        pg->policy_group_id,
                        (unsigned long long)g_scaffold_inplace_failures);
            check_scaffold_retry_threshold(pg->policy_group_id);
            g_scaffold_inplace_failures = 0;
            g_scaffold_skeleton_valid = 0;
        }
    } else if (did) {
        g_scaffold_inplace_failures = 0;
    }
    return did;
}

/* Execute Action DSL plan from policy group */
static int exec_action_dsl(ftfuzz_policy_group_t *pg,
                            unsigned char *buf, size_t *p_ns,
                            unsigned char **out_buf, size_t max_size,
                            int do_log) {
    /* For MVP, the DSL is stored in the JSON as action_dsl_plan.
     * Since we can't easily parse nested JSON from C, we use a simplified
     * approach: directly implement the primary+fallback logic for the
     * known XML attribute insertion pattern.
     *
     * Check: does the seed contain a start tag where we can insert?
     */
    size_t ns = *p_ns;
    size_t slot = 0;
    char id_value[64] = {0};
    unsigned int gen_counter = (unsigned int)(ns * 31 + pg->desired_outcome * 17);
    int did = 0;

    /* Primary path: FIND_START_TAG_ATTR_SLOT → GEN_IDENTIFIER_VALUE → INSERT_ATTRIBUTE */
    if (dsl_find_start_tag_attr_slot(buf, ns, &slot)) {
        if (do_log) log_msg("[ACTION] group=%s path=primary op=FIND_START_TAG_ATTR_SLOT result=success slot=%zu\n",
                pg->policy_group_id, slot);
        dsl_gen_identifier(id_value, sizeof(id_value), "ftid", &gen_counter);
        if (do_log) log_msg("[ACTION] group=%s path=primary op=GEN_IDENTIFIER_VALUE value=%s\n",
                pg->policy_group_id, id_value);
        if (dsl_insert_attribute(buf, &ns, slot, max_size, "xml:id", id_value)) {
            if (do_log) log_msg("[ACTION] group=%s path=primary op=INSERT_ATTRIBUTE attr=xml:id value=%s result=success\n",
                    pg->policy_group_id, id_value);
            *p_ns = ns;
            did = 1;
        } else {
            if (do_log) log_msg("[ACTION] group=%s path=primary op=INSERT_ATTRIBUTE result=fail reason=buffer_full\n",
                    pg->policy_group_id);
        }
    } else {
        if (do_log) log_msg("[ACTION] group=%s path=primary op=FIND_START_TAG_ATTR_SLOT result=fail reason=no_start_tag\n",
                pg->policy_group_id);
        /* Fallback: insert element pair at end */
        size_t fb_slot = ns;
        dsl_gen_identifier(id_value, sizeof(id_value), "ftid", &gen_counter);
        char elem_pair[512];
        snprintf(elem_pair, sizeof(elem_pair),
                 "<ftnode xml:id=\"%s\"></ftnode>", id_value);
        size_t tl = strlen(elem_pair);
        if (ns + tl <= max_size) {
            memcpy(buf + ns, elem_pair, tl);
            ns += tl;
            did = 1;
            if (do_log) log_msg("[ACTION] group=%s path=fallback op=INSERT_ELEMENT_PAIR_WITH_FIELD result=success value=%s\n",
                    pg->policy_group_id, id_value);
        } else {
            if (do_log) log_msg("[ACTION] group=%s path=fallback result=abort reason=buffer_full\n",
                    pg->policy_group_id);
        }
    }
    if (do_log) log_msg("[PLAN_RESULT] group=%s edit_success=%d\n",
            pg->policy_group_id, did);
    return did;
}

static int exec_ontology_action(ftfuzz_ontology_action_t *oa,
                                 ftfuzz_policy_group_t *pg,
                                 unsigned char *buf, size_t *p_ns,
                                 unsigned char **out_buf, size_t max_size,
                                 int do_log) {
    size_t ns = *p_ns;
    const char *op = oa->op;

    /* REMOVE_TOKENS: scan for evidence tokens, remove first match */
    if (!strcmp(op, "REMOVE_TOKENS")) {
        for (size_t ei = 0; ei < oa->evidence_token_count; ei++) {
            size_t pos, tl;
            if (_find_token(buf, ns, oa->evidence_tokens[ei], &pos, &tl)) {
                if (pos + tl <= ns) {
                    memmove(buf + pos, buf + pos + tl, ns - pos - tl);
                    *p_ns = ns - tl;
                    if (do_log) log_msg("[MUTATE_ONTO] group=%s action=%s op=REMOVE_TOKENS "
                            "removed=\"%s\" offset=%zu\n",
                            pg->policy_group_id, oa->action_id,
                            oa->evidence_tokens[ei], pos);
                    return 1;
                }
            }
        }
        return 0;
    }

    /* DELETE_REGION: remove bytes in focus range (or whole seed fallback) */
    if (!strcmp(op, "DELETE_REGION")) {
        if (pg->focus_range_count > 0) {
            ftfuzz_byte_range_t *fr = &pg->focus_ranges[rand() % pg->focus_range_count];
            if (fr->start < ns && fr->end <= ns && fr->start < fr->end) {
                size_t dellen = fr->end - fr->start;
                memmove(buf + fr->start, buf + fr->end, ns - fr->end);
                *p_ns = ns - dellen;
                if (do_log) log_msg("[MUTATE_ONTO] group=%s action=%s op=DELETE_REGION start=%u end=%u\n",
                        pg->policy_group_id, oa->action_id, fr->start, fr->end);
                return 1;
            }
        }
        /* Whole-seed deletion: remove a random chunk */
        if (ns > 4) {
            size_t start = rand() % (ns - 2);
            size_t dellen = 1 + (rand() % (ns - start));
            memmove(buf + start, buf + start + dellen, ns - start - dellen);
            *p_ns = ns - dellen;
            if (do_log) log_msg("[MUTATE_ONTO] group=%s action=%s op=DELETE_REGION start=%zu len=%zu (whole_seed)\n",
                    pg->policy_group_id, oa->action_id, start, dellen);
            return 1;
        }
        return 0;
    }

    /* EMPTY_REGION: replace focus range with minimal placeholder */
    if (!strcmp(op, "EMPTY_REGION")) {
        if (pg->focus_range_count > 0) {
            ftfuzz_byte_range_t *fr = &pg->focus_ranges[rand() % pg->focus_range_count];
            if (fr->start < ns && fr->end <= ns && fr->start < fr->end) {
                size_t rlen = fr->end - fr->start;
                char placeholder = ' ';
                /* Use first evidence token as placeholder if available */
                if (oa->evidence_token_count > 0 && oa->evidence_tokens[0][0])
                    placeholder = oa->evidence_tokens[0][0];
                memset(buf + fr->start, placeholder, rlen > 4 ? 4 : rlen);
                if (rlen > 4) {
                    memmove(buf + fr->start + 4, buf + fr->end, ns - fr->end);
                    *p_ns = ns - (rlen - 4);
                }
                if (do_log) log_msg("[MUTATE_ONTO] group=%s action=%s op=EMPTY_REGION start=%u end=%u\n",
                        pg->policy_group_id, oa->action_id, fr->start, fr->end);
                return 1;
            }
        }
        return 0;
    }

    /* INSERT_TOKEN_IN_REGION: insert evidence tokens in a grounded scope */
    if (!strcmp(op, "INSERT_TOKEN_IN_REGION")) {
        if (oa->evidence_token_count > 0) {
            int ti = rand() % oa->evidence_token_count;
            const char *tok = oa->evidence_tokens[ti];
            size_t tl = strlen(tok);
            if (_is_forbidden(tok, pg)) {
                g_forbidden_token_skips++;
                if (do_log) log_msg("[ONTO_FORBID] group=%s token=\"%s\" skipped\n",
                        pg->policy_group_id, tok);
                return 0;
            }
            if (tl > 0 && tl <= 128 && ns + tl <= max_size) {
                if (!g_insert_buf || g_insert_buf_size < max_size) {
                    free(g_insert_buf);
                    g_insert_buf = malloc(max_size);
                    g_insert_buf_size = g_insert_buf ? max_size : 0;
                }
                if (g_insert_buf) {
                    memcpy(g_insert_buf, buf, ns);
                    size_t pos = ns > 1 ? (rand() % (ns + 1)) : 0;
                    if (pg->insert_range_count > 0) {
                        ftfuzz_byte_range_t *ir = &pg->insert_ranges[rand() % pg->insert_range_count];
                        if (ir->start < ns) pos = ir->start + (ir->length > 1 ? (rand() % ir->length) : 0);
                    }
                    if (pos < ns) memmove(g_insert_buf + pos + tl, g_insert_buf + pos, ns - pos);
                    memcpy(g_insert_buf + pos, tok, tl);
                    *p_ns = ns + tl;
                    *out_buf = g_insert_buf; /* reuse buffer next call */
                    if (do_log) log_msg("[MUTATE_ONTO] group=%s action=%s op=INSERT_TOKEN_IN_REGION token=\"%s\" offset=%zu\n",
                            pg->policy_group_id, oa->action_id, tok, pos);
                    return 1;
                }
            }
        }
        return 0;
    }

    /* FOCUS_RANGE_HAVOC: apply standard havoc within a bounded range */
    if (!strcmp(op, "FOCUS_RANGE_HAVOC")) {
        if (pg->focus_range_count > 0 && ns > 0) {
            ftfuzz_byte_range_t *fr = &pg->focus_ranges[rand() % pg->focus_range_count];
            if (fr->length > 0 && fr->start < ns) {
                size_t pos = fr->start + (rand() % (fr->end < ns ? fr->end - fr->start + 1 : 1));
                if (pos < ns) {
                    buf[pos] ^= (unsigned char)((rand() % 255) + 1);
                    return 1;
                }
            }
        }
        return 0;
    }

    /* PRESERVE_REGION: no-op at mutator level (preservation is a constraint on other ops) */
    if (!strcmp(op, "PRESERVE_REGION") || !strcmp(op, "FORBID_TOKENS")) {
        return 0;  /* These operators are constraints, not active mutations */
    }

    /* REJECT_UNSUPPORTED: log and skip */
    if (!strcmp(op, "REJECT_UNSUPPORTED")) {
        if (do_log) log_msg("[MUTATE_ONTO] group=%s action=%s op=REJECT_UNSUPPORTED atom=%s\n",
                pg->policy_group_id, oa->action_id, oa->source_atom);
        return 0;
    }

    return 0;  /* unknown op or not implemented */
}

static int pg_index(const char *gid) {
    for (size_t i = 0; i < g_pg_count; i++)
        if (!strcmp(g_pg_ids[i], gid)) return (int)i;
    if (g_pg_count < PG_COUNTERS_MAX) {
        strncpy(g_pg_ids[g_pg_count], gid, FTFUZZ_MAX_ID_LEN - 1);
        return (int)g_pg_count++;
    }
    return -1;
}

static void log_msg(const char *fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap); va_end(ap);
    /* Flush every 1000 calls to reduce disk sync overhead */
    static uint64_t flush_counter = 0;
    if (++flush_counter % 1000 == 0) fflush(g_log);
}

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    (void)afl; (void)seed;
    const char *lp = getenv("FTFUZZ_MUTATOR_LOG");
    if (lp) g_log = fopen(lp, "a");
    if (!g_log) g_log = stderr;

    log_msg("=== FTFuzz Semantic Mutator Init (v2 policy_groups) ===\n");

    /* Check ablation mode */
    const char *abl = getenv("FTFUZZ_ABLATION");
    if (abl) {
        if (!strcmp(abl, "prefix"))  g_ablation_is_prefix = 1;
        if (!strcmp(abl, "action"))  g_ablation_is_action = 1;
        log_msg("[ABLATION] mode=%s prefix=%d action=%d\n", abl,
                g_ablation_is_prefix, g_ablation_is_action);
    }

    /* Load state_map for state_id -> transition_id conversion */
    int sm_count = ftfuzz_state_map_load(NULL);
    if (sm_count > 0)
        log_msg("[STATE_MAP] loaded %d entries for seed-state matching\n", sm_count);

    if (ftfuzz_policy_loader_init(NULL)) {
        ftfuzz_policy_loader_get_store(&g_store);
        g_loaded = 1;
        log_msg("[STORE] v%lu schema=%s mode=%s groups=%zu mappings=%zu\n",
                (unsigned long)g_store.store_version,
                g_store.schema_version, g_store.activation_mode,
                g_store.policy_group_count, g_store.transition_mapping_count);
        for (size_t i = 0; i < g_store.policy_group_count && i < 8; i++) {
            ftfuzz_policy_group_t *pg = &g_store.policy_groups[i];
            log_msg("[GROUP] %s source=%s model=%s enabled=%d priority=%.2f tokens=%zu members=%zu\n",
                    pg->policy_group_id, pg->semantic_source, pg->llm_model,
                    pg->enabled, pg->priority, pg->dictionary_token_count,
                    pg->member_transition_count);
        }
    } else {
        log_msg("[INIT] no policy store, havoc-only mode\n");
    }
    srand(seed ^ time(NULL));
    return (void *)1;
}

const char *afl_custom_queue_get(void *data, const unsigned char *filename) {
    (void)data;
    g_queue_get_calls++;
    if (filename) snprintf(g_last_seed, sizeof(g_last_seed), "%s", (const char *)filename);
    return (const char *)filename;
}

size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t buf_size,
                       unsigned char **out_buf, unsigned char *add_buf,
                       size_t add_buf_size, size_t max_size) {
    (void)data; (void)add_buf; (void)add_buf_size;
    g_calls++;

    /* Hot reload — detect policy_store version change */
    /* Throttled reload check — every 32 calls OR every 5 seconds */
    {
        static time_t last_reload_check_sec = 0;
        time_t now = time(NULL);
        int time_triggered = (now - last_reload_check_sec >= 5);
        int call_triggered = ((g_calls & 0x1F) == 0);  /* every 32 calls */
        if ((call_triggered || time_triggered) && ftfuzz_policy_loader_reload_if_needed()) {
            ftfuzz_policy_loader_get_store(&g_store);
            g_reloads++;
            g_loaded = 1;  /* Fix: mark store as loaded on hot-reload */
            g_cached_has_pol = -1;
            g_last_sidecar_seed[0] = 0;
            g_scaffold_rebuild_success = 0;   /* reset: new policy may have new scaffold */
            g_scaffold_skeleton_valid = 0;
            last_reload_check_sec = now;
            log_msg("[RELOAD] v%lu groups=%zu mappings=%zu\n",
                    (unsigned long)g_store.store_version,
                    g_store.policy_group_count, g_store.transition_mapping_count);
        }
    }

    /* Seed-state-conditioned policy group selection */
    ftfuzz_policy_group_t sel;
    char sel_tid[FTFUZZ_MAX_ID_LEN] = {0};
    char sel_sc[64] = {0};
    memset(&sel, 0, sizeof(sel));
    int has_pol = 0;

    if (g_loaded && g_last_seed[0]) {
        /* Cache: only re-read sidecar when seed actually changes */
        if (strcmp(g_last_seed, g_last_sidecar_seed) != 0) {
            strncpy(g_last_sidecar_seed, g_last_seed, sizeof(g_last_sidecar_seed) - 1);
            char sc_path[1024];
            /* AFL++ passes basename only; prepend queue dir if set */
            const char *qdir = getenv("FTFUZZ_QUEUE_DIR");
            if (qdir && g_last_seed[0] != '/') {
                snprintf(sc_path, sizeof(sc_path), "%s/%s.ftstate.json", qdir, g_last_seed);
            } else {
                snprintf(sc_path, sizeof(sc_path), "%s.ftstate.json", g_last_seed);
            }
            g_ftstate_attempts++;
            g_selection_attempts++;

            g_cached_has_pol = ftfuzz_policy_loader_select_for_seed(
                g_last_seed, sc_path, &g_cached_sel,
                g_cached_tid, sizeof(g_cached_tid), g_cached_sc, sizeof(g_cached_sc));

            if (g_cached_has_pol) {
                g_ftstate_success++;
                g_selection_success++;
                int pi = pg_index(g_cached_sel.policy_group_id);
                if (pi >= 0) g_pg_selections[pi]++;
                log_msg("[SELECT] seed=%s transition=%s state=%s group=%s score=%.2f tokens=%zu\n",
                        g_last_seed, g_cached_tid, g_cached_sc, g_cached_sel.policy_group_id,
                        g_cached_sel.priority + 1.0, g_cached_sel.dictionary_token_count);
            } else {
                g_ftstate_fail++;
                g_selection_fallback++;
            }
        }
        has_pol = g_cached_has_pol > 0;
        sel = g_cached_sel;
        strncpy(sel_tid, g_cached_tid, sizeof(sel_tid) - 1);
        strncpy(sel_sc, g_cached_sc, sizeof(sel_sc) - 1);
    }

    /* Fallback: top-priority enabled group (cached) */
    if (!has_pol && g_loaded && g_store.policy_group_count > 0) {
        if (g_cached_has_pol <= 0) {  /* compute on first miss or after failed select */
            g_selection_fallback++;
            double best = -1;
            for (size_t i = 0; i < g_store.policy_group_count; i++) {
                ftfuzz_policy_group_t *pg = &g_store.policy_groups[i];
                if (pg->enabled && pg->priority > best) {
                    best = pg->priority;
                    g_cached_sel = *pg;
                    g_cached_has_pol = 1;
                }
            }
            if (g_cached_has_pol > 0) {
                strncpy(g_cached_tid, g_cached_sel.representative_transition, sizeof(g_cached_tid) - 1);
                /* Check if this is the active blocked transition with ontology actions */
                size_t active_n = 0;
                for (size_t oi = 0; oi < g_cached_sel.ontology_action_count; oi++) {
                    const char *oop = g_cached_sel.ontology_actions[oi].op;
                    if (strcmp(oop, "PRESERVE_REGION") && strcmp(oop, "FORBID_TOKENS") &&
                        strcmp(oop, "REJECT_UNSUPPORTED")) active_n++;
                }
                if (active_n > 0) {
                    log_msg("[SELECT_ACTIVE_FALLBACK] seed=%s transition=%s group=%s active_actions=%zu\n",
                            g_last_seed, g_cached_tid, g_cached_sel.policy_group_id, active_n);
                } else {
                    log_msg("[SELECT] seed=%s no_matching_transition fallback=priority group=%s\n",
                            g_last_seed, g_cached_sel.policy_group_id);
                }
            }
        }
        has_pol = g_cached_has_pol > 0;
        sel = g_cached_sel;
        strncpy(sel_tid, g_cached_tid, sizeof(sel_tid) - 1);
    }

    /* Legacy fallback: top-priority flat policy (cached) */
    if (!has_pol && g_loaded && g_store.policy_count > 0) {
        g_selection_fallback++;
        has_pol = 1;
        /* Minimal: just mark as having a policy, no group data */
    }

    size_t ns = buf_size;
    int did = 0;

    /* Log throttling — only on every 128th call or first few calls */
    int do_log = (g_calls < 10 || g_calls % 128 == 0);

    if (do_log && has_pol && (sel.preserve_range_count > 0 || sel.focus_range_count > 0)) {
        log_msg("[RANGE] group=%s preserve=%zu focus=%zu insert=%zu\n",
                sel.policy_group_id, sel.preserve_range_count,
                sel.focus_range_count, sel.insert_range_count);
    }

    /* Try mutations in priority order. Only malloc when growing the buffer. */
    if (has_pol && sel.enabled) {
        double r = (double)rand() / RAND_MAX;

        /* Stage 2.7: Per-execution preserve mask.
         * PaST-Prefix ablation: mask disabled — no prefix preservation. */
        ftfuzz_preserve_mask_t chain_mask;
        memset(&chain_mask, 0, sizeof(chain_mask));
        if (sel.preserve_mask.enabled && !g_ablation_is_prefix) {
            chain_mask.enabled = 1;
            chain_mask.max_protected_ratio = sel.preserve_mask.max_protected_ratio;
        }

        /* Stage 2.7: Detect scaffold-produced seeds — protect their structure.
         * PaST-Prefix ablation: no scaffold protection — all seeds treated equally. */
        int is_scaffold_seed = 0;
        if (g_scaffold_skeleton_valid && !g_ablation_is_prefix) {
            uint32_t cur_hash = compute_skeleton_hash(buf, ns);
            if (cur_hash == g_scaffold_skeleton_hash) {
                is_scaffold_seed = 1;
                if (do_log) log_msg("[SCAFFOLD_PROTECT] seed matched scaffold skeleton — "
                        "prioritizing in-place chain\n");
            }
        }
        /* Boost chain probability for scaffold seeds: 0.80 instead of 0.40.
         * PaST-Prefix: no boost — always use base probability. */
        double chain_prob = (is_scaffold_seed && !g_ablation_is_prefix) ? 0.80 : 0.40;
        /* Suppress random havoc for scaffold seeds.
         * PaST-Prefix: no suppression — always allow havoc. */
        double havoc_suppress = (is_scaffold_seed && !g_ablation_is_prefix) ? 0.0 : 1.0;

        /* 0. Action Chain (Stage 2.7 — IF_PRECONDITION_ELSE_SCAFFOLD + Donor, highest priority)
         * PaST-Action ablation: skip action chain — LLM generates scaffold seeds directly. */
        int chain_attempted = 0;
        double r_chain = ((double)rand() / RAND_MAX);  /* independent random per dispatch */
        if (!did && pg_index(sel.policy_group_id) >= 0 &&
            r_chain < chain_prob && !g_ablation_is_action) {
            chain_attempted = 1;
            if (exec_action_chain(&sel, buf, &ns, out_buf, max_size, do_log, &chain_mask)) {
                did = 1;
                g_chain_consecutive_failures = 0;  /* reset on success */
            }
        }

        /* ── Layer 2 & 3: Auto-construct + escalation on chain failure ── */
        if (!did && chain_attempted &&
            g_chain_consecutive_failures > 0 &&
            (g_chain_consecutive_failures % 100) == 0 &&
            g_chain_consecutive_failures <= 500) {

            /* Layer 2: build minimal seed from FIND patterns.
             * Creates a fresh buffer by inserting FIND patterns in dependency
             * order — does not depend on current seed content. */
            if (g_auto_construct_attempts < 3) {
                unsigned char build_buf[4096];
                size_t build_len = 0;
                int build_ok = 1;

                for (size_t si = 0; si < sel.action_step_count && build_ok; si++) {
                    ftfuzz_action_step_t *st = &sel.action_steps[si];
                    if (strcmp(st->op, "FIND")) continue;
                    const char *phex = NULL, *out = NULL;
                    for (int pi = 0; pi < st->param_count; pi++) {
                        if (!strcmp(st->param_keys[pi], "pattern")) phex = st->param_values[pi];
                        if (!strcmp(st->param_keys[pi], "output")) out = st->param_values[pi];
                    }
                    if (!phex || !out) continue;
                    unsigned char pat[256];
                    size_t plen = decode_data(phex, pat, sizeof(pat));
                    if (plen == 0 || build_len + plen > sizeof(build_buf)) { build_ok = 0; break; }
                    /* Check if pattern already exists in build buffer */
                    int already = 0;
                    for (size_t i = 0; i + plen <= build_len; i++)
                        if (!memcmp(build_buf + i, pat, plen)) { already = 1; break; }
                    if (!already) {
                        /* Check start dependency: if FIND has {ref} start, resolve it */
                        uint32_t insert_at = (uint32_t)build_len;
                        const char *start_str = NULL;
                        for (int pi = 0; pi < st->param_count; pi++)
                            if (!strcmp(st->param_keys[pi], "start")) start_str = st->param_values[pi];
                        if (start_str && start_str[0] == '{') {
                            /* Find the ref in already-built patterns (simplified: use build offset map) */
                            const char *close = strchr(start_str, '}');
                            if (close) {
                                size_t nl = (size_t)(close - start_str - 1);
                                /* Search build_buf for the referenced pattern */
                                int resolved = 0;
                                for (size_t si2 = 0; si2 < si && !resolved; si2++) {
                                    ftfuzz_action_step_t *st2 = &sel.action_steps[si2];
                                    if (strcmp(st2->op, "FIND")) continue;
                                    const char *out2 = NULL;
                                    for (int pi = 0; pi < st2->param_count; pi++)
                                        if (!strcmp(st2->param_keys[pi], "output")) out2 = st2->param_values[pi];
                                    if (out2 && !strncmp(out2, start_str + 1, nl) && out2[nl] == 0) {
                                        const char *p2 = NULL;
                                        for (int pi = 0; pi < st2->param_count; pi++)
                                            if (!strcmp(st2->param_keys[pi], "pattern")) p2 = st2->param_values[pi];
                                        if (p2) {
                                            unsigned char p2b[256];
                                            size_t p2l = decode_data(p2, p2b, sizeof(p2b));
                                            for (size_t i = 0; i + p2l <= build_len; i++)
                                                if (!memcmp(build_buf + i, p2b, p2l))
                                                    { insert_at = (uint32_t)(i + p2l); resolved = 1; break; }
                                        }
                                    }
                                }
                                if (!resolved) insert_at = (uint32_t)build_len;
                            }
                        }
                        memmove(build_buf + insert_at + plen, build_buf + insert_at, build_len - insert_at);
                        memcpy(build_buf + insert_at, pat, plen);
                        build_len += plen;
                    }
                }

                if (build_ok && build_len > 0) {
                    g_auto_construct_attempts++;
                    /* Try executing chain on the constructed buffer */
                    size_t test_ns = build_len;
                    if (build_len > max_size) test_ns = max_size;
                    memcpy(buf, build_buf, test_ns);
                    ns = test_ns;
                    if (exec_action_chain(&sel, buf, &ns, out_buf, max_size, 0, &chain_mask)) {
                        did = 1;
                        g_auto_construct_success++;
                        g_chain_consecutive_failures = 0;
                        g_auto_construct_attempts = 0;
                        if (do_log) log_msg("[AUTO_BUILD] chain=%s success len=%zu\n",
                                sel.policy_group_id, ns);
                    } else if (do_log) {
                        log_msg("[AUTO_BUILD] chain=%s failed attempt=%llu\n",
                                sel.policy_group_id,
                                (unsigned long long)g_auto_construct_attempts);
                    }
                }
            }
        }

        /* Layer 3: escalate persistent failure to scaffold rebuild */
        if (!did && g_chain_consecutive_failures >= 500 &&
            g_chain_consecutive_failures % 500 == 0 &&
            sel.scaffold_template_len > 0) {
            if (do_log) log_msg("[CHAIN_FAIL_ESCALATE] chain=%s failures=%llu — forcing scaffold\n",
                    sel.policy_group_id, (unsigned long long)g_chain_consecutive_failures);
            /* Trigger scaffold path by simulating precond failure */
            unsigned int l3_counter = (unsigned int)(ns * 31 + sel.desired_outcome * 17);
            if (instantiate_scaffold(buf, &ns, max_size, sel.scaffold_template,
                                      sel.scaffold_template_len,
                                      &l3_counter, do_log, sel.policy_group_id)) {
                check_scaffold_retry_threshold(sel.policy_group_id);
                if (exec_action_chain(&sel, buf, &ns, out_buf, max_size, do_log, &chain_mask)) {
                    did = 1;
                    g_chain_consecutive_failures = 0;
                    g_auto_construct_attempts = 0;
                }
            }
        }

        /* 0b. Action DSL Plan — BLOCKED when chain was attempted (Stage 2.6: disable known-invalid) */
        double r_dsl = ((double)rand() / RAND_MAX);
        if (!did && !chain_attempted && pg_index(sel.policy_group_id) >= 0 &&
            r_dsl < 0.40) {
            if (exec_action_dsl(&sel, buf, &ns, out_buf, max_size, do_log)) {
                did = 1;
            }
        } else if (!did && chain_attempted && do_log) {
            g_known_invalid_fallback_blocked++;
            log_msg("[FALLBACK_DISABLED] action=INSERT_ATTRIBUTE attr=xml:id "
                    "reason=known_invalid_for_state_goal group=%s\n", sel.policy_group_id);
        }

        /* 0b. ontology_action_plan (Stage 2.3-fix) */
        double r_onto = ((double)rand() / RAND_MAX);
        if (!did && sel.ontology_action_count > 0 && sel.desired_outcome != -1 &&
            r_onto < 0.35) {
            g_onto_attempts++;
            /* Log plan on first attempt for this group */
            static char last_onto_group[128] = {0};
            if (strcmp(last_onto_group, sel.policy_group_id) != 0 && do_log) {
                size_t active_n = 0, passive_n = 0;
                for (size_t oi = 0; oi < sel.ontology_action_count; oi++) {
                    const char *oop = sel.ontology_actions[oi].op;
                    if (!strcmp(oop, "PRESERVE_REGION") || !strcmp(oop, "FORBID_TOKENS"))
                        passive_n++;
                    else if (!strcmp(oop, "REJECT_UNSUPPORTED"))
                        ;
                    else
                        active_n++;
                }
                log_msg("[ONTO_PLAN] group=%s desired=%s actions=%zu active=%zu passive=%zu forbidden=%zu\n",
                        sel.policy_group_id,
                        sel.desired_outcome ? "true" : "false",
                        sel.ontology_action_count, active_n, passive_n,
                        sel.forbidden_token_count);
                strncpy(last_onto_group, sel.policy_group_id, sizeof(last_onto_group) - 1);
            }
            /* Try up to 3 random ontology actions */
            for (int oa_try = 0; oa_try < 3 && !did; oa_try++) {
                int oa_idx = rand() % sel.ontology_action_count;
                ftfuzz_ontology_action_t *oa = &sel.ontology_actions[oa_idx];
                int is_active = (strcmp(oa->op, "PRESERVE_REGION") != 0 &&
                                 strcmp(oa->op, "FORBID_TOKENS") != 0 &&
                                 strcmp(oa->op, "REJECT_UNSUPPORTED") != 0);
                if (is_active) g_active_mut_attempts++;
                if (exec_ontology_action(oa, &sel, buf, &ns, out_buf, max_size, do_log)) {
                    g_onto_success++;
                    if (is_active) g_active_mut_success++;
                    else g_passive_constraint_applied++;
                    /* Per-op counter */
                    int op_hash = oa->op[0] + oa->op[1]*31;
                    if (op_hash >= 0 && op_hash < 32) g_per_op_success[op_hash & 31]++;
                    did = 1;
                } else {
                    g_onto_rejected++;
                }
            }
            if (!did) g_onto_fallback++;
        }

        /* 0. semantic_edit: region-reuse operations (format-agnostic) */
        if (!did && sel.edit_plan_enabled && sel.semantic_edit_op_count > 0 &&
            r < 0.30) {
            g_semantic_edit_attempts++;
            int op_idx = rand() % sel.semantic_edit_op_count;
            ftfuzz_semantic_edit_op_t *eo = &sel.semantic_edit_ops[op_idx];
            if (op_idx < FTFUZZ_MAX_EDIT_OPS) g_edit_op_counts[op_idx]++;

            /* EXTEND_TAIL: works without ranges — just append existing bytes */
            if (!strcmp(eo->op, "EXTEND_TAIL_BY_EXISTING_REGION") && ns > 4 && ns + 64 <= max_size) {
                size_t src_start = ns > 32 ? ns - 32 : 0;
                size_t copy_len = (rand() % 16) + 4;
                if (!g_insert_buf || g_insert_buf_size < max_size) {
                    free(g_insert_buf); g_insert_buf = malloc(max_size); g_insert_buf_size = g_insert_buf ? max_size : 0;
                }
                if (g_insert_buf) {
                    memcpy(g_insert_buf, buf, ns);
                    memcpy(g_insert_buf + ns, buf + src_start, copy_len);
                    ns += copy_len; did = 1; g_semantic_edit_success++;
                    *out_buf = g_insert_buf; /* reuse buffer next call */
                    if (do_log) log_msg("[EDIT] group=%s op=EXTEND_TAIL_BY_EXISTING_REGION src=%zu len=%zu\n",
                            sel.policy_group_id, src_start, copy_len);
                }
            }
            /* Region-reuse ops that need focus or insert ranges */
            else if (sel.focus_range_count > 0 || sel.insert_range_count > 0) {
                ftfuzz_byte_range_t *fr = sel.focus_range_count > 0 ?
                    &sel.focus_ranges[rand() % sel.focus_range_count] :
                    &sel.insert_ranges[rand() % sel.insert_range_count];

                /* Validate focus range: start < end, both within buffer */
                int fr_valid = (fr->start < fr->end && fr->end <= ns);

                if (!strcmp(eo->op, "EXTEND_AFTER_FOCUS_REGION") && fr_valid && fr->end + 32 <= max_size) {
                    size_t src_start = rand() % (ns > 0 ? ns : 1);
                    size_t copy_len = (rand() % 32) + 4;
                    if (src_start + copy_len <= ns) {
                        if (!g_insert_buf || g_insert_buf_size < max_size) {
                            free(g_insert_buf); g_insert_buf = malloc(max_size); g_insert_buf_size = g_insert_buf ? max_size : 0;
                        }
                        if (g_insert_buf) {
                            memcpy(g_insert_buf, buf, ns);
                            memmove(g_insert_buf + fr->end + copy_len, g_insert_buf + fr->end, ns - fr->end);
                            memcpy(g_insert_buf + fr->end, g_insert_buf + src_start, copy_len);
                            ns += copy_len; did = 1; g_semantic_edit_success++;
                            *out_buf = g_insert_buf; /* reuse buffer next call */
                        }
                    }
                }
                else if (!strcmp(eo->op, "DUPLICATE_REGION") && fr_valid && ns + (fr->end - fr->start) <= max_size) {
                    size_t copy_len = fr->end - fr->start;
                    if (copy_len > 0) {
                        if (!g_insert_buf || g_insert_buf_size < max_size) {
                            free(g_insert_buf); g_insert_buf = malloc(max_size); g_insert_buf_size = g_insert_buf ? max_size : 0;
                        }
                        if (g_insert_buf) {
                            memcpy(g_insert_buf, buf, ns);
                            memmove(g_insert_buf + fr->end + copy_len, g_insert_buf + fr->end, ns - fr->end);
                            memcpy(g_insert_buf + fr->end, buf + fr->start, copy_len);
                            ns += copy_len; did = 1; g_semantic_edit_success++;
                            *out_buf = g_insert_buf; /* reuse buffer next call */
                        }
                    }
                }
                else if (!strcmp(eo->op, "REPLACE_FOCUS_WITH_EXISTING_REGION") && ns > 0) {
                    size_t src_start = rand() % (ns > 0 ? ns : 1);
                    size_t copy_len = (rand() % (fr->length > 0 ? fr->length : 16)) + 2;
                    if (src_start + copy_len <= ns && fr->start + copy_len <= ns) {
                        memcpy(buf + fr->start, buf + src_start, copy_len);
                        did = 1; g_semantic_edit_success++;
                    }
                }
            }
        }

        /* 1. insert_focus: grow buffer (reusable, AFL doesn't free custom mutator output) */
        if (!did && sel.insert_range_count > 0 && sel.dictionary_token_count > 0 &&
            r < sel.op_region_focus) {
            ftfuzz_byte_range_t *ir = &sel.insert_ranges[rand() % sel.insert_range_count];
            int idx = rand() % sel.dictionary_token_count;
            const char *tok = sel.dictionary_tokens[idx].token;
            size_t tl = strlen(tok);
            if (tl > 0 && tl <= 128 && ns + tl <= max_size && ir->length > 0) {
                if (!g_insert_buf || g_insert_buf_size < max_size) {
                    free(g_insert_buf);
                    g_insert_buf = malloc(max_size);
                    g_insert_buf_size = g_insert_buf ? max_size : 0;
                }
                if (g_insert_buf) {
                    memcpy(g_insert_buf, buf, ns);
                    size_t pos = ir->start < ns ? ir->start + (rand() % (ir->end < ns ? ir->end - ir->start + 1 : 1)) : ns;
                    if (pos < ns) memmove(g_insert_buf + pos + tl, g_insert_buf + pos, ns - pos);
                    memcpy(g_insert_buf + pos, tok, tl);
                    ns += tl; g_insertions++; g_range_insertions++; did = 1;
                    int pi = pg_index(sel.policy_group_id);
                    if (pi >= 0) g_pg_insertions[pi]++;
                    if (do_log) log_msg("[FUZZ] insert_focus group=%s token=\"%s\" range=%u-%u offset=%zu\n",
                            sel.policy_group_id, tok, ir->start, ir->end, pos);
                    *out_buf = g_insert_buf; /* reuse buffer next call */
                }
            }
        }

        /* 2. focus_havoc: in-place, skip protected ranges if mask active.
         * Suppressed for scaffold seeds to preserve structural integrity.
         * PaST-Prefix: mask checks skipped — allow havoc anywhere. */
        if (!did && sel.focus_range_count > 0 && ns > 0 &&
            r < (sel.op_region_focus + 0.15) * havoc_suppress) {
            ftfuzz_byte_range_t *fr = &sel.focus_ranges[rand() % sel.focus_range_count];
            if (fr->length > 0) {
                size_t pos;
                if (g_ablation_is_prefix) {
                    pos = fr->start < ns ? fr->start + (rand() % (fr->end < ns ? fr->end - fr->start + 1 : 1)) : rand() % ns;
                    if (pos < ns) { buf[pos] ^= (unsigned char)((rand() % 255) + 1); g_focus_havoc++; did = 1; }
                } else {
                    int tries = 0;
                    do {
                        pos = fr->start < ns ? fr->start + (rand() % (fr->end < ns ? fr->end - fr->start + 1 : 1)) : rand() % ns;
                        tries++;
                    } while (tries < 20 && mask_contains(&chain_mask, pos, 0 /* no_havoc */));
                    if (pos < ns && !mask_contains(&chain_mask, pos, 0)) {
                        buf[pos] ^= (unsigned char)((rand() % 255) + 1);
                        g_focus_havoc++; did = 1;
                        if (chain_mask.enabled && tries > 1) g_masked_mutation_skipped++;
                    }
                }
            }
        }

        /* 3. preserve_aware_havoc: in-place, avoid static preserve + dynamic mask ranges.
         * Suppressed for scaffold seeds to preserve structural integrity.
         * PaST-Prefix: mask checks skipped — simple random byte flip. */
        if (!did && (sel.preserve_range_count > 0 || chain_mask.enabled || g_ablation_is_prefix) && ns > 0 &&
            r < (sel.op_region_focus + 0.15 + sel.op_fallback_havoc) * havoc_suppress) {
            if (g_ablation_is_prefix) {
                size_t pos = rand() % ns;
                buf[pos] ^= (unsigned char)((rand() % 255) + 1);
                g_preserve_aware++; did = 1;
            } else {
                size_t pos; int tries = 0;
                do { pos = rand() % ns; tries++; }
                while (tries < 20 && (_in_preserve(pos, &sel) ||
                       mask_contains(&chain_mask, pos, 0)));
                buf[pos] ^= (unsigned char)((rand() % 255) + 1);
                g_preserve_aware++; did = 1;
                if (chain_mask.enabled && tries > 1) g_masked_mutation_skipped++;
            }
        }

        /* 4. dictionary_insert: grow buffer (reusable) — obey forbidden tokens */
        if (!did && sel.dictionary_token_count > 0 &&
            sel.op_dictionary_insert > 0.0 &&
            r < sel.op_dictionary_insert + sel.op_region_focus + 0.15 + sel.op_fallback_havoc) {
            g_attempts++;
            int idx = rand() % sel.dictionary_token_count;
            const char *tok = sel.dictionary_tokens[idx].token;
            /* Check forbidden tokens (from ontology action plan) */
            if (_is_forbidden(tok, &sel)) {
                g_forbidden_token_skips++;
                if (do_log) log_msg("[ONTO_FORBID] group=%s token=\"%s\" skipped (dictionary_insert)\n",
                        sel.policy_group_id, tok);
                /* Don't count as did — fall through to fallback */
            } else {
            size_t tl = strlen(tok);
            if (tl > 0 && tl <= 128 && ns + tl <= max_size) {
                if (!g_insert_buf || g_insert_buf_size < max_size) {
                    free(g_insert_buf);
                    g_insert_buf = malloc(max_size);
                    g_insert_buf_size = g_insert_buf ? max_size : 0;
                }
                if (g_insert_buf) {
                    memcpy(g_insert_buf, buf, ns);
                    size_t pos = ns > 0 ? rand() % (ns + 1) : 0;
                    if (pos < ns) memmove(g_insert_buf + pos + tl, g_insert_buf + pos, ns - pos);
                    memcpy(g_insert_buf + pos, tok, tl);
                    ns += tl; g_insertions++; did = 1;
                    int pi = pg_index(sel.policy_group_id);
                    if (pi >= 0) g_pg_insertions[pi]++;
                    *out_buf = g_insert_buf; /* reuse buffer next call */
                }
            }
            }  /* end else (!is_forbidden) */
        }
    }

    if (!did) {
        g_fallbacks++;
        /* For scaffold-produced seeds, skip the random byte flip — it would
         * destroy the carefully-constructed format bytes (SQL/JSON/ELF).
         * Instead, return the seed as-is; the preserve mask already protects
         * critical ranges from AFL's havoc.
         * PaST-Prefix ablation: always allow random flip. */
        if (g_ablation_is_prefix ||
            !g_scaffold_skeleton_valid ||
            compute_skeleton_hash(buf, ns) != g_scaffold_skeleton_hash) {
            if (ns > 0) buf[rand() % ns] ^= (unsigned char)((rand() % 255) + 1);
        }
    }

    if (!did || *out_buf == NULL) *out_buf = buf;
    return ns;
}

size_t afl_custom_post_process(void *data, unsigned char *buf,
                                size_t buf_size, unsigned char **out_buf) {
    (void)data; *out_buf = buf; return buf_size;
}

/* ── Stage 2.7: Custom trim hooks — skip AFL's built-in trimming ──
 *
 * AFL's trim stage removes bytes that don't affect coverage. For scaffold
 * and in-place chain outputs, this destroys carefully constructed structure
 * (e.g. <!ELEMENT, <?xml declarations) that may matter for later validation
 * paths even if they don't immediately change the bitmap.
 *
 * Returning 0 from init_trim tells AFL to skip trimming entirely for this
 * seed, preserving the full structural skeleton. */

s32 afl_custom_init_trim(void *data, u8 *buf, size_t buf_size) {
    (void)data; (void)buf; (void)buf_size;
    /* Stage 2.7: Always skip AFL's trim for custom mutator outputs.
     * The scaffold template and in-place chain produce structurally
     * complete seeds where every byte was intentionally placed.
     * NOTE: We cannot enable trim even in PaST-Prefix ablation because
     * afl_custom_trim() is not implemented (returns 0 = failure in AFL). */
    if (g_log) {
        static uint64_t trim_skip_count = 0;
        if (++trim_skip_count <= 5)
            log_msg("[TRIM_SKIP] seed_len=%zu — skipping AFL trim to preserve structure\n", buf_size);
    }
    return 0;  /* 0 iterations = skip trimming */
}

size_t afl_custom_trim(void *data, u8 **out_buf) {
    (void)data; (void)out_buf;
    return 0;  /* Never called if init_trim returns 0, but define anyway */
}

s32 afl_custom_post_trim(void *data, u8 success) {
    (void)data; (void)success;
    return -1;  /* Stop trimming */
}

void afl_custom_deinit(void *data) {
    (void)data;
    log_msg("=== Deinit ===\n");
    log_msg("[STATS] queue_get=%lu ftstate_load=%lu/%lu/%lu "
            "selections=%lu/%lu/%lu reloads=%lu calls=%lu\n",
            (unsigned long)g_queue_get_calls,
            (unsigned long)g_ftstate_success, (unsigned long)g_ftstate_fail,
            (unsigned long)g_ftstate_attempts,
            (unsigned long)g_selection_success, (unsigned long)g_selection_fallback,
            (unsigned long)g_selection_attempts,
            (unsigned long)g_reloads, (unsigned long)g_calls);
    log_msg("[STATS] dictionary attempts=%lu insertions=%lu fallbacks=%lu\n",
            (unsigned long)g_attempts, (unsigned long)g_insertions,
            (unsigned long)g_fallbacks);
    log_msg("[STATS] range_insertions=%lu focus_havoc=%lu preserve_aware=%lu\n",
            (unsigned long)g_range_insertions, (unsigned long)g_focus_havoc,
            (unsigned long)g_preserve_aware);
    log_msg("[STATS] semantic_edit attempts=%lu success=%lu\n",
            (unsigned long)g_semantic_edit_attempts, (unsigned long)g_semantic_edit_success);
    log_msg("[STATS] ontology_actions_attempted=%lu success=%lu rejected=%lu fallback=%lu\n",
            (unsigned long)g_onto_attempts, (unsigned long)g_onto_success,
            (unsigned long)g_onto_rejected, (unsigned long)g_onto_fallback);
    log_msg("[STATS] ontology_active_mutation attempts=%lu success=%lu passive_applied=%lu\n",
            (unsigned long)g_active_mut_attempts, (unsigned long)g_active_mut_success,
            (unsigned long)g_passive_constraint_applied);
    log_msg("[STATS] forbidden_token_skips=%lu\n",
            (unsigned long)g_forbidden_token_skips);
    log_msg("[STATS] chain_precheck attempts=%lu pass=%lu fail=%lu\n",
            (unsigned long)g_chain_precheck_attempts,
            (unsigned long)g_chain_precondition_pass,
            (unsigned long)g_chain_precondition_fail);
    log_msg("[STATS] chain_inplace attempts=%lu success=%lu\n",
            (unsigned long)g_chain_inplace_attempts,
            (unsigned long)g_chain_inplace_success);
    log_msg("[STATS] scaffold_rebuild attempts=%lu success=%lu rejected=%lu\n",
            (unsigned long)g_scaffold_rebuild_attempts,
            (unsigned long)g_scaffold_rebuild_success,
            (unsigned long)g_scaffold_rebuild_rejected);
    log_msg("[STATS] chain_ineligible=%lu known_invalid_fallback_blocked=%lu\n",
            (unsigned long)g_chain_ineligible,
            (unsigned long)g_known_invalid_fallback_blocked);
    log_msg("[STATS] chain_donor attempts=%lu success=%lu miss=%lu scanned=%lu\n",
            (unsigned long)g_chain_donor_attempts, (unsigned long)g_chain_donor_success,
            (unsigned long)g_chain_donor_miss, (unsigned long)g_donor_seeds_scanned_total);
    log_msg("[STATS] chain_current attempts=%lu success=%lu no_base_skip=%lu\n",
            (unsigned long)g_chain_current_attempts, (unsigned long)g_chain_current_success,
            (unsigned long)g_chain_no_base_skip);
    log_msg("[STATS] preserve_mask created=%lu ranges=%lu bytes=%lu "
            "skipped=%lu limit=%lu binding_survival=%lu\n",
            (unsigned long)g_preserve_mask_created, (unsigned long)g_preserve_mask_ranges_total,
            (unsigned long)g_protected_bytes_total, (unsigned long)g_masked_mutation_skipped,
            (unsigned long)g_mask_limit_triggered, (unsigned long)g_binding_key_survival_success);
    for (size_t i = 0; i < FTFUZZ_MAX_EDIT_OPS; i++) {
        if (g_edit_op_counts[i] > 0 && i < g_store.policy_group_count) {
            ftfuzz_policy_group_t *pg = &g_store.policy_groups[0]; /* find the group with ops */
            for (size_t gi = 0; gi < g_store.policy_group_count; gi++) {
                if (g_store.policy_groups[gi].semantic_edit_op_count > 0) {
                    pg = &g_store.policy_groups[gi];
                    if (i < pg->semantic_edit_op_count)
                        log_msg("[STATS] edit_op=%s count=%lu\n",
                                pg->semantic_edit_ops[i].op, (unsigned long)g_edit_op_counts[i]);
                }
            }
        }
    }

    /* Per-group counters */
    for (size_t i = 0; i < g_pg_count; i++) {
        if (g_pg_selections[i] > 0 || g_pg_insertions[i] > 0)
            log_msg("[STATS] group=%s selections=%lu insertions=%lu\n",
                    g_pg_ids[i],
                    (unsigned long)g_pg_selections[i],
                    (unsigned long)g_pg_insertions[i]);
    }

    ftfuzz_policy_loader_destroy();
    if (g_insert_buf) { free(g_insert_buf); g_insert_buf = NULL; g_insert_buf_size = 0; }
    if (g_log && g_log != stderr) fclose(g_log);
    g_log = NULL;
}
