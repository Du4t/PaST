#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include "dgf_rt.h"

static dgf_shm_t *g_dgf_shm = NULL;
static int g_dgf_shmid = -1;

static void __attribute__((constructor)) _dgf_rt_auto_init(void) {
    __dgf_rt_init();
}

static void __attribute__((destructor)) _dgf_rt_auto_fini(void) {
    if (g_dgf_shm && g_dgf_shmid >= 0) {
        shmdt(g_dgf_shm);
    }
}

void __dgf_rt_init(void) {
    if (g_dgf_shm) return;

    /* Prefer the per-target DGF_SHMID env var (set by THIS target's own AFL
       via IPC_PRIVATE). This is correct under parallel multi-target runs.
       The shared /tmp/ftfuzz_dgf_shm file is last-writer-wins, so checking it
       first would cross-contaminate parallel targets. */
    char *env_shmid = getenv("DGF_SHMID");
    if (env_shmid) {
        g_dgf_shmid = (int)strtol(env_shmid, NULL, 10);
        g_dgf_shm = (dgf_shm_t *)shmat(g_dgf_shmid, NULL, 0);
        if (g_dgf_shm != (void *)-1) return;
        g_dgf_shm = NULL;
    }

    /* Fallback: shared file (single-target runs, or fork-server env-passthrough
       failure). Safe because only one AFL is expected to have written it. */
    {
        FILE *sf = fopen("/tmp/ftfuzz_dgf_shm", "r");
        if (sf) {
            int shmid;
            if (fscanf(sf, "%d", &shmid) == 1) {
                fclose(sf);
                g_dgf_shmid = shmid;
                g_dgf_shm = (dgf_shm_t *)shmat(shmid, NULL, 0);
                if (g_dgf_shm != (void *)-1) return;
                g_dgf_shm = NULL;
            } else { fclose(sf); }
        }
    }

    /* Final fallback: fixed-key shmget (single-process) */
    g_dgf_shmid = shmget(DGF_SHM_KEY, sizeof(dgf_shm_t), IPC_CREAT | 0600);
    if (g_dgf_shmid < 0) return;
    g_dgf_shm = (dgf_shm_t *)shmat(g_dgf_shmid, NULL, 0);
    if (g_dgf_shm == (void *)-1) {
        g_dgf_shm = NULL;
        shmctl(g_dgf_shmid, IPC_RMID, NULL);
        return;
    }
    memset((void *)g_dgf_shm, 0xFF, sizeof(dgf_shm_t));
    g_dgf_shm->min_distance = DGF_INF_DISTANCE;
    g_dgf_shm->sum_distance = 0;
    g_dgf_shm->hit_count = 0;
    g_dgf_shm->reached_target = 0;
}

void __dgf_rt_record_bb_distance(uint32_t bb_id, uint32_t scaled_distance) {
    if (!g_dgf_shm) return;

    if (bb_id < DGF_MAX_BB_ENTRIES) {
        g_dgf_shm->bb_distances[bb_id] = scaled_distance;
    }

    if (scaled_distance == 0) {
        g_dgf_shm->reached_target = 1;
    }

    if (scaled_distance < g_dgf_shm->min_distance) {
        g_dgf_shm->min_distance = scaled_distance;
    }

    if (scaled_distance < DGF_INF_DISTANCE) {
        __sync_fetch_and_add(&g_dgf_shm->sum_distance, scaled_distance);
        __sync_fetch_and_add(&g_dgf_shm->hit_count, 1);
    }
}

/* Alias used by TargetDistancePass instrumentation */
void __dgf_record_bb_distance(uint32_t bb_id, uint32_t scaled_distance)
    __attribute__((alias("__dgf_rt_record_bb_distance")));

void __dgf_rt_reset(void) {
    if (!g_dgf_shm) return;
    g_dgf_shm->min_distance = DGF_INF_DISTANCE;
    g_dgf_shm->sum_distance = 0;
    g_dgf_shm->hit_count = 0;
    g_dgf_shm->reached_target = 0;
}

dgf_shm_t *__dgf_rt_get_shm(void) {
    return g_dgf_shm;
}
