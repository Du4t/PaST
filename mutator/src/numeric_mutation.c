#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "numeric_mutation.h"

static uint32_t simple_rng(uint32_t *seed) {
    *seed = (*seed * 1103515245 + 12345) & 0x7fffffff;
    return *seed;
}

static uint64_t read_be(const unsigned char *buf, uint32_t width) {
    uint64_t val = 0;
    for (uint32_t i = 0; i < width && i < 8; i++) {
        val = (val << 8) | buf[i];
    }
    return val;
}

static uint64_t read_le(const unsigned char *buf, uint32_t width) {
    uint64_t val = 0;
    for (uint32_t i = 0; i < width && i < 8; i++) {
        val |= ((uint64_t)buf[i]) << (i * 8);
    }
    return val;
}

static void write_be(unsigned char *buf, uint64_t val, uint32_t width) {
    for (uint32_t i = 0; i < width && i < 8; i++) {
        buf[width - 1 - i] = (unsigned char)(val & 0xff);
        val >>= 8;
    }
}

static void write_le(unsigned char *buf, uint64_t val, uint32_t width) {
    for (uint32_t i = 0; i < width && i < 8; i++) {
        buf[i] = (unsigned char)(val & 0xff);
        val >>= 8;
    }
}

uint64_t numeric_read_field(const unsigned char *buf, size_t buf_size,
                             const numeric_field_t *field) {
    if (field->start + field->width > buf_size) return 0;
    const unsigned char *ptr = buf + field->start;
    if (strcmp(field->endian, "big") == 0) {
        return read_be(ptr, field->width);
    } else {
        return read_le(ptr, field->width);
    }
}

void numeric_write_field(unsigned char *buf, size_t buf_size,
                          const numeric_field_t *field, uint64_t value) {
    if (field->start + field->width > buf_size) return;
    unsigned char *ptr = buf + field->start;
    if (strcmp(field->endian, "big") == 0) {
        write_be(ptr, value, field->width);
    } else {
        write_le(ptr, value, field->width);
    }
}

uint64_t numeric_apply_action(uint64_t current, numeric_action_e action,
                               uint64_t rhs_hint, unsigned int *rng_seed) {
    uint64_t mask = 0;
    switch (action) {
        case ACTION_INC: {
            int64_t delta = (int64_t)(simple_rng(rng_seed) % 64) - 16;
            if (delta < 0 && (uint64_t)(-delta) > current) return 0;
            return current + delta;
        }
        case ACTION_DEC: {
            int64_t delta = (int64_t)(simple_rng(rng_seed) % 32);
            if ((uint64_t)delta > current) return 0;
            return current - delta;
        }
        case ACTION_RANDOM_DELTA: {
            uint64_t delta = simple_rng(rng_seed);
            delta = (delta % 256) + 1;
            if (simple_rng(rng_seed) % 2 == 0) {
                return current + delta;
            } else {
                if (delta > current) return 0;
                return current - delta;
            }
        }
        case ACTION_BOUNDARY: {
            static const uint64_t boundaries[] = {
                0, 1, 0xff, 0x100, 0xffff, 0x10000,
                0x7fffffff, 0x80000000, 0xffffffff,
                15, 16, 31, 32, 63, 64, 65,
                127, 128, 255, 256,
                1024, 4096, 8192, 16384, 32768, 65536,
                0xffffffffffffffffULL,
            };
            uint32_t idx = simple_rng(rng_seed) % (sizeof(boundaries) / sizeof(boundaries[0]));
            return boundaries[idx];
        }
        case ACTION_FIT_RHS: {
            if (rhs_hint > 0) {
                uint64_t delta = simple_rng(rng_seed) % 32;
                if (rhs_hint >= delta) return rhs_hint - delta;
            }
            return rhs_hint;
        }
        default:
            return current;
    }
    return current;
}

size_t numeric_mutate(unsigned char *buf, size_t buf_size,
                       const mutation_policy_t *policy, unsigned int *rng_seed) {
    if (policy->num_numeric_fields == 0) return buf_size;

    uint32_t field_idx = simple_rng(rng_seed) % policy->num_numeric_fields;
    const numeric_field_t *field = &policy->numeric_fields[field_idx];

    if (field->start + field->width > buf_size) return buf_size;

    uint64_t current = numeric_read_field(buf, buf_size, field);

    uint32_t act_idx = simple_rng(rng_seed) % field->num_actions;
    numeric_action_e action = field->actions[act_idx];

    uint64_t new_val = numeric_apply_action(action, 0, 0, rng_seed);

    numeric_write_field(buf, buf_size, field, new_val);
    return buf_size;
}
