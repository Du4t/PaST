/*
 * FTFuzz DGF Shared Memory Layout
 *
 * This header must remain ABI-compatible with runtime/include/dgf_rt.h.
 * Any change to the dgf_shm_t struct must be reflected in both files.
 *
 * This file is used by AFL++ to access DGF shared memory without
 * depending on the full FTFuzz runtime.
 */

#ifndef FTFUZZ_DGF_SHM_H
#define FTFUZZ_DGF_SHM_H

#include <stdint.h>
#include <stddef.h>

#define FTFUZZ_DGF_SHM_KEY       0xAFF00002U
#define FTFUZZ_DGF_MAX_BB_ENTRIES 131072
#define FTFUZZ_DGF_INF_DISTANCE   0xFFFFFFFFU

typedef struct {
    volatile uint32_t min_distance;
    volatile uint32_t sum_distance;
    volatile uint32_t hit_count;
    volatile uint8_t  reached_target;
    volatile uint8_t  padding[3];
    volatile uint32_t bb_distances[FTFUZZ_DGF_MAX_BB_ENTRIES];
} ftfuzz_dgf_shm_t;

/* Compile-time size check */
#define FTFUZZ_DGF_SHM_EXPECTED_SIZE \
    (sizeof(uint32_t) * 3 + sizeof(uint8_t) * 4 + sizeof(uint32_t) * FTFUZZ_DGF_MAX_BB_ENTRIES)

#endif /* FTFUZZ_DGF_SHM_H */
