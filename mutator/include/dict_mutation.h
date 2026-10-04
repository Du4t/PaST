#ifndef DICT_MUTATION_H
#define DICT_MUTATION_H

#include "mutation_policy.h"
#include <stdint.h>
#include <stddef.h>

size_t dict_mutate(unsigned char *buf, size_t buf_size,
                    const mutation_policy_t *policy, unsigned int *rng_seed);

#endif
