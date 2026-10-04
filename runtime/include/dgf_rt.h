#ifndef DGF_RT_H
#define DGF_RT_H

#include <stdint.h>
#include <stddef.h>

#define DGF_SHM_KEY 0xAFF00002
#define DGF_MAX_BB_ENTRIES 131072
#define DGF_INF_DISTANCE 0xFFFFFFFFU

typedef struct {
    volatile uint32_t min_distance;
    volatile uint32_t sum_distance;
    volatile uint32_t hit_count;
    volatile uint8_t  reached_target;
    volatile uint8_t  padding[3];
    volatile uint32_t bb_distances[DGF_MAX_BB_ENTRIES];
} dgf_shm_t;

void __dgf_rt_init(void);
void __dgf_rt_record_bb_distance(uint32_t bb_id, uint32_t scaled_distance);
void __dgf_rt_reset(void);
dgf_shm_t *__dgf_rt_get_shm(void);

#endif
