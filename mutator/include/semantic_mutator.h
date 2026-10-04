#ifndef SEMANTIC_MUTATOR_H
#define SEMANTIC_MUTATOR_H

#include "mutation_policy.h"
#include "policy_loader.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    policy_loader_t loader;
    uint32_t trials_since_gain;
    uint32_t total_mutations;
    uint32_t policy_mutations;
    uint32_t fallback_mutations;
    unsigned int rng_seed;
} semantic_mutator_t;

void semantic_mutator_init(semantic_mutator_t *sm, const char *policy_path, unsigned int seed);
size_t semantic_mutator_fuzz(semantic_mutator_t *sm,
                              const unsigned char *buf, size_t buf_size,
                              unsigned char **out_buf,
                              size_t max_size);
void semantic_mutator_deinit(semantic_mutator_t *sm);

#endif
