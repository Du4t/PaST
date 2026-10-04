#ifndef FUZZ_RT_H
#define FUZZ_RT_H

#include <stdint.h>
#include <stddef.h>

#define MAX_BARRIERS 4096
#define MAX_TRANSITIONS 4096
#define CMP_RING_SIZE 8192
#define SNAPSHOT_RING_SIZE 4096

#define FUZZ_SHM_KEY 0xAFF00001
#define FUZZ_SHM_SIZE (sizeof(fuzz_shm_t))

typedef struct {
    uint64_t lhs;
    uint64_t rhs;
    uint32_t barrier_id;
    uint32_t predicate;
    uint32_t outcome;
    uint32_t source_line;
    char source_file[64];
} cmp_record_t;

typedef struct {
    uint32_t barrier_id;
    uint32_t variable_id;
    uint64_t value;
} snapshot_record_t;

typedef struct {
    volatile uint32_t current_execution_id;
    volatile uint32_t min_distance;
    volatile uint32_t current_barrier_id;
    volatile uint32_t barrier_hit_count[MAX_BARRIERS];
    volatile uint32_t pre_hit_count[MAX_TRANSITIONS];
    volatile uint32_t transition_barrier_hit_count[MAX_TRANSITIONS];
    volatile uint32_t post_hit_count[MAX_TRANSITIONS];

    volatile uint32_t cmp_write_idx;
    cmp_record_t cmp_records[CMP_RING_SIZE];

    volatile uint32_t snapshot_write_idx;
    snapshot_record_t snapshot_records[SNAPSHOT_RING_SIZE];

    volatile uint32_t initialized;
} fuzz_shm_t;

void __fuzz_rt_init(void);
void __fuzz_rt_record_bb(uint32_t bb_id, uint32_t distance);
void __fuzz_rt_record_cmp(uint32_t barrier_id, uint64_t lhs, uint64_t rhs,
                           uint32_t predicate, uint32_t outcome);
void __fuzz_rt_record_state_hit(uint32_t state_id);
void __fuzz_rt_record_pre_hit(uint32_t transition_id);
void __fuzz_rt_record_barrier_hit(uint32_t transition_id);
void __fuzz_rt_record_post_hit(uint32_t transition_id);
void __fuzz_rt_record_branch_barrier(uint32_t transition_id, uint8_t target_taken);
void __fuzz_rt_record_snapshot(uint32_t barrier_id, uint32_t variable_id, uint64_t value);

fuzz_shm_t *__fuzz_rt_get_shm(void);

#endif
