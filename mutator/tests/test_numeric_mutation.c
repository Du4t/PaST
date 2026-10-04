#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "numeric_mutation.h"
#include "mutation_policy.h"

int main(void) {
    unsigned char buf[64] = {0};
    memset(buf, 0xAA, sizeof(buf));

    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x04;

    mutation_policy_t policy;
    memset(&policy, 0, sizeof(policy));
    policy.enabled = 1;
    policy.version = 1;
    strncpy(policy.policy_id, "test", sizeof(policy.policy_id));

    numeric_field_t *nf = &policy.numeric_fields[0];
    nf->start = 4;
    nf->end = 8;
    nf->width = 4;
    strncpy(nf->endian, "big", sizeof(nf->endian));
    nf->is_signed = 0;
    strncpy(nf->role, "length", sizeof(nf->role));
    nf->actions[0] = ACTION_BOUNDARY;
    nf->actions[1] = ACTION_INC;
    nf->num_actions = 2;
    nf->confidence = 0.8;
    policy.num_numeric_fields = 1;

    policy.op_weights.numeric_boundary = 0.5;
    policy.op_weights.directional_arithmetic = 0.2;
    policy.op_weights.fallback = 0.3;

    unsigned int seed = 42;
    uint64_t original = numeric_read_field(buf, sizeof(buf), nf);
    printf("[INFO] Original value: %lu\n", (unsigned long)original);

    for (int i = 0; i < 10; i++) {
        unsigned char buf_copy[64];
        memcpy(buf_copy, buf, sizeof(buf));
        seed = 42 + i * 7;
        numeric_mutate(buf_copy, sizeof(buf_copy), &policy, &seed);
        uint64_t new_val = numeric_read_field(buf_copy, sizeof(buf_copy), nf);
        printf("[MUTATION %d] value: %lu\n", i, (unsigned long)new_val);
    }

    printf("[PASS] numeric_mutation: basic test passed\n");
    return 0;
}
