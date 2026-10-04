#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "semantic_mutator.h"
#include "numeric_mutation.h"
#include "dict_mutation.h"
#include "repair_rules.h"

extern size_t fallback_mutation(unsigned char *buf, size_t buf_size,
                                 size_t max_size, unsigned int *rng_seed);

static uint32_t simple_rng(uint32_t *seed) {
    *seed = (*seed * 1103515245 + 12345) & 0x7fffffff;
    return *seed;
}

static int is_in_preserve_range(const mutation_policy_t *policy, uint32_t offset) {
    for (uint32_t i = 0; i < policy->num_preserve_ranges; i++) {
        const preserve_range_t *pr = &policy->preserve_ranges[i];
        if (offset >= pr->start && offset < pr->end) return 1;
    }
    return 0;
}

static int is_in_focus_range(const mutation_policy_t *policy, uint32_t offset) {
    for (uint32_t i = 0; i < policy->num_focus_ranges; i++) {
        const focus_range_t *fr = &policy->focus_ranges[i];
        if (offset >= fr->start && offset < fr->end) return 1;
    }
    return 0;
}

static double get_preserve_weight(const mutation_policy_t *policy, uint32_t offset) {
    for (uint32_t i = 0; i < policy->num_preserve_ranges; i++) {
        const preserve_range_t *pr = &policy->preserve_ranges[i];
        if (offset >= pr->start && offset < pr->end) return pr->weight;
    }
    return 0.0;
}

static double get_focus_weight(const mutation_policy_t *policy, uint32_t offset) {
    for (uint32_t i = 0; i < policy->num_focus_ranges; i++) {
        const focus_range_t *fr = &policy->focus_ranges[i];
        if (offset >= fr->start && offset < fr->end) return fr->weight;
    }
    return 0.0;
}

static size_t apply_range_aware_mutation(semantic_mutator_t *sm,
                                          const unsigned char *buf, size_t buf_size,
                                          unsigned char *out, size_t max_size) {
    const mutation_policy_t *policy = policy_loader_get(&sm->loader);
    if (!policy || !policy->enabled) return 0;

    memcpy(out, buf, buf_size < max_size ? buf_size : max_size);
    size_t out_size = buf_size < max_size ? buf_size : max_size;

    uint32_t mutations_applied = 0;
    uint32_t max_mutations = out_size > 0 ? out_size / 4 + 1 : 1;

    for (uint32_t m = 0; m < max_mutations && mutations_applied < 3; m++) {
        uint32_t offset = simple_rng(&sm->rng_seed) % (out_size > 0 ? out_size : 1);

        double preserve_w = get_preserve_weight(policy, offset);
        double focus_w = get_focus_weight(policy, offset);

        double r = (double)(simple_rng(&sm->rng_seed) % 10000) / 10000.0;

        if (preserve_w > 0 && r < preserve_w) {
            continue;
        }

        if (focus_w > 0) {
            out[offset] ^= (1 << (simple_rng(&sm->rng_seed) % 8));
            mutations_applied++;
        } else {
            if (r > 0.5) {
                out[offset] ^= (1 << (simple_rng(&sm->rng_seed) % 8));
                mutations_applied++;
            }
        }
    }

    return out_size;
}

void semantic_mutator_init(semantic_mutator_t *sm, const char *policy_path, unsigned int seed) {
    memset(sm, 0, sizeof(*sm));
    sm->rng_seed = seed ? seed : (unsigned int)time(NULL);
    policy_loader_init(&sm->loader, policy_path);
}

size_t semantic_mutator_fuzz(semantic_mutator_t *sm,
                              const unsigned char *buf, size_t buf_size,
                              unsigned char **out_buf,
                              size_t max_size) {
    policy_loader_try_reload(&sm->loader);
    const mutation_policy_t *policy = policy_loader_get(&sm->loader);

    *out_buf = (unsigned char *)malloc(max_size);
    if (!*out_buf) return 0;

    size_t out_size = buf_size;
    if (out_size > max_size) out_size = max_size;

    if (!policy || !policy->enabled) {
        memcpy(*out_buf, buf, out_size);
        out_size = fallback_mutation((unsigned char *)*out_buf, out_size, max_size, &sm->rng_seed);
        sm->fallback_mutations++;
        sm->total_mutations++;
        return out_size;
    }

    memcpy(*out_buf, buf, out_size);

    double total_weight = policy->op_weights.numeric_boundary
                        + policy->op_weights.directional_arithmetic
                        + policy->op_weights.byte_pattern_insert
                        + policy->op_weights.repair
                        + policy->op_weights.fallback;

    if (total_weight <= 0) {
        out_size = fallback_mutation((unsigned char *)*out_buf, out_size, max_size, &sm->rng_seed);
        sm->fallback_mutations++;
        sm->total_mutations++;
        return out_size;
    }

    double r = (double)(simple_rng(&sm->rng_seed) % 10000) / 10000.0 * total_weight;
    double cum = 0;

    cum += policy->op_weights.numeric_boundary;
    if (r < cum) {
        out_size = apply_range_aware_mutation(sm, buf, buf_size, *out_buf, max_size);
        out_size = numeric_mutate(*out_buf, out_size, policy, &sm->rng_seed);
        sm->policy_mutations++;
        sm->total_mutations++;
        return out_size;
    }

    cum += policy->op_weights.directional_arithmetic;
    if (r < cum) {
        out_size = numeric_mutate(*out_buf, out_size, policy, &sm->rng_seed);
        sm->policy_mutations++;
        sm->total_mutations++;
        return out_size;
    }

    cum += policy->op_weights.byte_pattern_insert;
    if (r < cum) {
        out_size = dict_mutate(*out_buf, out_size, policy, &sm->rng_seed);
        sm->policy_mutations++;
        sm->total_mutations++;
        return out_size;
    }

    cum += policy->op_weights.repair;
    if (r < cum) {
        out_size = repair_apply(*out_buf, out_size, policy, &sm->rng_seed);
        sm->policy_mutations++;
        sm->total_mutations++;
        return out_size;
    }

    out_size = fallback_mutation((unsigned char *)*out_buf, out_size, max_size, &sm->rng_seed);
    sm->fallback_mutations++;
    sm->total_mutations++;
    return out_size;
}

void semantic_mutator_deinit(semantic_mutator_t *sm) {
    (void)sm;
}
