/*
 * FTFuzz State Transition Shared Memory Layout (barrier-only, simplified)
 *
 * ABI-compatible with runtime/src/state_rt.c.
 * Pre/Post hit tracking removed: DGF distance provides "reached" and "crossed".
 */

#ifndef FTFUZZ_STATE_SHM_H
#define FTFUZZ_STATE_SHM_H

#include <stdint.h>

#define FTFUZZ_STATE_SHM_KEY       0xAFF00001U
#define FTFUZZ_MAX_TRANSITIONS     4096

typedef struct {
    volatile uint32_t transition_barrier_hit_count[FTFUZZ_MAX_TRANSITIONS];
    volatile uint32_t target_edge_taken_count[FTFUZZ_MAX_TRANSITIONS];
    volatile uint32_t non_target_edge_taken_count[FTFUZZ_MAX_TRANSITIONS];
    volatile uint32_t barrier_branch_exec_count[FTFUZZ_MAX_TRANSITIONS];
} ftfuzz_state_shm_t;

#endif /* FTFUZZ_STATE_SHM_H */
