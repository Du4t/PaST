#ifndef POLICY_FORMAT_H
#define POLICY_FORMAT_H

#include "fuzz_rt.h"

#define POLICY_SHM_NAME "ftfuzz_policy_shm"
#define POLICY_SHM_SIZE (256 * 1024)

typedef struct {
    volatile uint32_t version;
    volatile uint32_t enabled;
    volatile uint32_t data_len;
    char json_data[POLICY_SHM_SIZE - 12];
} policy_shm_t;

#endif
