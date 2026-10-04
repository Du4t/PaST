#ifndef REPAIR_RULES_H
#define REPAIR_RULES_H

#include "mutation_policy.h"
#include <stdint.h>
#include <stddef.h>

size_t repair_apply(unsigned char *buf, size_t buf_size,
                     const mutation_policy_t *policy, unsigned int *rng_seed);

#endif
