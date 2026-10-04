#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dict_mutation.h"

static uint32_t simple_rng(uint32_t *seed) {
    *seed = (*seed * 1103515245 + 12345) & 0x7fffffff;
    return *seed;
}

size_t dict_mutate(unsigned char *buf, size_t buf_size,
                    const mutation_policy_t *policy, unsigned int *rng_seed) {
    if (policy->num_dict_tokens == 0) return buf_size;

    double total_weight = 0;
    for (uint32_t i = 0; i < policy->num_dict_tokens; i++) {
        total_weight += policy->dict_tokens[i].weight;
    }
    if (total_weight <= 0) return buf_size;

    double r = (double)(simple_rng(rng_seed) % 10000) / 10000.0 * total_weight;
    double cum = 0;
    const dict_token_t *token = NULL;
    for (uint32_t i = 0; i < policy->num_dict_tokens; i++) {
        cum += policy->dict_tokens[i].weight;
        if (r <= cum) {
            token = &policy->dict_tokens[i];
            break;
        }
    }
    if (!token) token = &policy->dict_tokens[0];

    if (policy->num_focus_ranges > 0) {
        uint32_t fi = simple_rng(rng_seed) % policy->num_focus_ranges;
        const focus_range_t *fr = &policy->focus_ranges[fi];
        if (fr->start + token->len <= buf_size) {
            memcpy(buf + fr->start, token->bytes, token->len);
        }
    } else {
        uint32_t insert_pos = simple_rng(rng_seed) % (buf_size > 0 ? buf_size : 1);
        if (insert_pos + token->len <= buf_size) {
            memcpy(buf + insert_pos, token->bytes, token->len);
        }
    }

    return buf_size;
}
