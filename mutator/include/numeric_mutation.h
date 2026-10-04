#ifndef NUMERIC_MUTATION_H
#define NUMERIC_MUTATION_H

#include "mutation_policy.h"
#include <stdint.h>
#include <stddef.h>

uint64_t numeric_read_field(const unsigned char *buf, size_t buf_size,
                             const numeric_field_t *field);
void numeric_write_field(unsigned char *buf, size_t buf_size,
                          const numeric_field_t *field, uint64_t value);
uint64_t numeric_apply_action(uint64_t current, numeric_action_e action,
                               uint64_t rhs_hint, unsigned int *rng_seed);
size_t numeric_mutate(unsigned char *buf, size_t buf_size,
                       const mutation_policy_t *policy, unsigned int *rng_seed);

#endif
