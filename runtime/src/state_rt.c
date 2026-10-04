#include "fuzz_rt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <string.h>

/*
 * State shared memory — barrier-only (simplified Stage 2.3-fix).
 *
 * Pre/Post hit tracking removed: DGF distance data already provides
 * "reached" (min_distance) and "crossed" (distance decrease) signals.
 * Only barrier branch direction needs dedicated instrumentation.
 *
 * AFL++ creates this (key=0xAFF00001), passes shmid via FTFUZZ_SHMID.
 */

#define STATE_SHM_KEY 0xAFF00001U
#define STATE_MAX_TRANSITIONS 4096

typedef struct {
    volatile uint32_t transition_barrier_hit_count[STATE_MAX_TRANSITIONS];
    volatile uint32_t target_edge_taken_count[STATE_MAX_TRANSITIONS];
    volatile uint32_t non_target_edge_taken_count[STATE_MAX_TRANSITIONS];
    volatile uint32_t barrier_branch_exec_count[STATE_MAX_TRANSITIONS];
} state_shm_t;

static state_shm_t *g_state_shm = NULL;
static int g_state_shmid = -1;

static void __attribute__((constructor)) _state_rt_auto_init(void) {
    /* Prefer per-target FTFUZZ_SHMID env (set by THIS target's own AFL via
       IPC_PRIVATE) — correct under parallel runs. The shared file is
       last-writer-wins, so checking it first would cross-contaminate targets. */
    char *env_shmid = getenv("FTFUZZ_SHMID");
    if (env_shmid) {
        g_state_shmid = (int)strtol(env_shmid, NULL, 10);
        g_state_shm = (state_shm_t *)shmat(g_state_shmid, NULL, 0);
        if (g_state_shm != (void *)-1) { memset((void *)g_state_shm, 0, sizeof(state_shm_t)); return; }
        g_state_shm = NULL;
    }
    /* Fallback: shared file (single-target, or env-passthrough failure) */
    {
        FILE *sf = fopen("/tmp/ftfuzz_state_shm", "r");
        if (sf) {
            int shmid;
            if (fscanf(sf, "%d", &shmid) == 1) {
                fclose(sf);
                g_state_shmid = shmid;
                g_state_shm = (state_shm_t *)shmat(shmid, NULL, 0);
                if (g_state_shm != (void *)-1) { memset((void *)g_state_shm, 0, sizeof(state_shm_t)); return; }
                g_state_shm = NULL;
            } else { fclose(sf); }
        }
    }
    /* Final fallback: fixed-key shmget (single-process) */
    g_state_shmid = shmget(STATE_SHM_KEY, sizeof(state_shm_t), IPC_CREAT | 0600);
    if (g_state_shmid >= 0) {
        g_state_shm = (state_shm_t *)shmat(g_state_shmid, NULL, 0);
        if (g_state_shm == (void *)-1) {
            g_state_shm = NULL;
            shmctl(g_state_shmid, IPC_RMID, NULL);
        } else {
            memset((void *)g_state_shm, 0, sizeof(state_shm_t));
        }
    }
}

static void __attribute__((destructor)) _state_rt_auto_fini(void) {
    if (g_state_shm && g_state_shmid >= 0) shmdt(g_state_shm);
}

/* Barrier hit (BB-fallback: no direction info) */
void __fuzz_rt_record_barrier_hit(uint32_t transition_id) {
    if (!g_state_shm) return;
    if (transition_id < STATE_MAX_TRANSITIONS) {
        __sync_fetch_and_add(&g_state_shm->transition_barrier_hit_count[transition_id], 1);
    }
}

/* Branch barrier with direction tracking */
void __fuzz_rt_record_branch_barrier(uint32_t transition_id, uint8_t target_taken) {
    if (!g_state_shm) return;
    if (transition_id < STATE_MAX_TRANSITIONS) {
        __sync_fetch_and_add(&g_state_shm->barrier_branch_exec_count[transition_id], 1);
        __sync_fetch_and_add(&g_state_shm->transition_barrier_hit_count[transition_id], 1);
        if (target_taken) {
            __sync_fetch_and_add(&g_state_shm->target_edge_taken_count[transition_id], 1);
        } else {
            __sync_fetch_and_add(&g_state_shm->non_target_edge_taken_count[transition_id], 1);
        }
    }
}

/* Legacy compat — maps to barrier_hit */
void __fuzz_rt_record_state_hit(uint32_t state_id) {
    __fuzz_rt_record_barrier_hit(state_id);
}

/* Removed: record_pre_hit, record_post_hit — redundant with DGF distance */
