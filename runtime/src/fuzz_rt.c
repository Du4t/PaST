#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include "fuzz_rt.h"

/*
 * DGF (Directed Greybox Fuzzing) shared memory.
 * AFL++ creates the DGF shared memory (key=0xAFF00002) and passes the shmid
 * via DGF_SHMID environment variable.  We attach to it for distance tracking.
 *
 * Note: State hit tracking is handled separately by state_rt.c which uses
 * FTFUZZ_SHMID (key=0xAFF00001) with the ftfuzz_state_shm_t layout.
 */

#define DGF_MAX_BB_ENTRIES 131072

typedef struct {
    volatile uint32_t min_distance;
    volatile uint32_t sum_distance;
    volatile uint32_t hit_count;
    volatile uint8_t  reached_target;
    volatile uint8_t  padding[3];
    volatile uint32_t bb_distances[DGF_MAX_BB_ENTRIES];
} dgf_shm_t;

static dgf_shm_t *g_dgf_shm = NULL;
static int g_dgf_shmid = -1;

static void __attribute__((constructor)) _fuzz_rt_auto_init(void) {
    char *env_shmid = getenv("DGF_SHMID");
    if (env_shmid) {
        g_dgf_shmid = (int)strtol(env_shmid, NULL, 10);
        g_dgf_shm = (dgf_shm_t *)shmat(g_dgf_shmid, NULL, 0);
        if (g_dgf_shm == (void *)-1) {
            g_dgf_shm = NULL;
        }
    }
}

static void __attribute__((destructor)) _fuzz_rt_auto_fini(void) {
    if (g_dgf_shm && g_dgf_shmid >= 0) {
        shmdt(g_dgf_shm);
    }
}

void __fuzz_rt_init(void) {
    /* Already initialized by constructor */
}

void __fuzz_rt_record_bb(uint32_t bb_id, uint32_t distance) {
    if (!g_dgf_shm) return;
    if (distance < g_dgf_shm->min_distance || g_dgf_shm->min_distance == 0) {
        g_dgf_shm->min_distance = distance;
    }
    if (bb_id < DGF_MAX_BB_ENTRIES) {
        g_dgf_shm->bb_distances[bb_id] = distance;
    }
}

void __fuzz_rt_record_cmp(uint32_t barrier_id, uint64_t lhs, uint64_t rhs,
                           uint32_t predicate, uint32_t outcome) {
    /* CMP tracking not used in current AFL++ integration */
    (void)barrier_id; (void)lhs; (void)rhs; (void)predicate; (void)outcome;
}

void __fuzz_rt_record_snapshot(uint32_t barrier_id, uint32_t variable_id, uint64_t value) {
    /* Snapshot tracking not used in current AFL++ integration */
    (void)barrier_id; (void)variable_id; (void)value;
}
