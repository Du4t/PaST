#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "repair_rules.h"

static uint64_t read_be(const unsigned char *buf, uint32_t width) {
    uint64_t val = 0;
    for (uint32_t i = 0; i < width && i < 8; i++) {
        val = (val << 8) | buf[i];
    }
    return val;
}

static void write_be(unsigned char *buf, uint64_t val, uint32_t width) {
    for (uint32_t i = 0; i < width && i < 8; i++) {
        buf[width - 1 - i] = (unsigned char)(val & 0xff);
        val >>= 8;
    }
}

static uint64_t read_le(const unsigned char *buf, uint32_t width) {
    uint64_t val = 0;
    for (uint32_t i = 0; i < width && i < 8; i++) {
        val |= ((uint64_t)buf[i]) << (i * 8);
    }
    return val;
}

static void write_le(unsigned char *buf, uint64_t val, uint32_t width) {
    for (uint32_t i = 0; i < width && i < 8; i++) {
        buf[i] = (unsigned char)(val & 0xff);
        val >>= 8;
    }
}

size_t repair_apply(unsigned char *buf, size_t buf_size,
                     const mutation_policy_t *policy, unsigned int *rng_seed) {
    (void)rng_seed;

    for (uint32_t r = 0; r < policy->num_repair_rules; r++) {
        const repair_rule_t *rule = &policy->repair_rules[r];

        switch (rule->type) {
            case REPAIR_LENGTH_RECOMPUTE: {
                if (rule->length_end > buf_size || rule->payload_start > buf_size)
                    break;
                uint32_t len_width = rule->length_end - rule->length_start;
                uint32_t payload_size = 0;
                if (rule->payload_end <= buf_size) {
                    payload_size = rule->payload_end - rule->payload_start;
                } else {
                    payload_size = (uint32_t)buf_size - rule->payload_start;
                }
                if (len_width > 0 && len_width <= 8 && rule->length_start + len_width <= buf_size) {
                    unsigned char *len_ptr = buf + rule->length_start;
                    if (strcmp(rule->endian, "big") == 0) {
                        write_be(len_ptr, payload_size, len_width);
                    } else {
                        write_le(len_ptr, payload_size, len_width);
                    }
                }
                break;
            }
            case REPAIR_PAYLOAD_SIZE_FIT: {
                if (rule->length_end > buf_size) break;
                uint32_t len_width = rule->length_end - rule->length_start;
                if (len_width == 0 || len_width > 8) break;
                if (rule->length_start + len_width > buf_size) break;

                unsigned char *len_ptr = buf + rule->length_start;
                uint64_t claimed_len;
                if (strcmp(rule->endian, "big") == 0) {
                    claimed_len = read_be(len_ptr, len_width);
                } else {
                    claimed_len = read_le(len_ptr, len_width);
                }

                uint64_t available = 0;
                if (rule->payload_start < buf_size) {
                    available = buf_size - rule->payload_start;
                }
                if (claimed_len > available) {
                    if (strcmp(rule->endian, "big") == 0) {
                        write_be(len_ptr, available, len_width);
                    } else {
                        write_le(len_ptr, available, len_width);
                    }
                }
                break;
            }
            case REPAIR_CHECKSUM_NOOP:
            default:
                break;
        }
    }

    return buf_size;
}
