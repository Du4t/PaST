#include "fuzz_rt.h"
#include <stdint.h>

void __fuzz_rt_record_cmp_observation(uint32_t barrier_id, uint64_t lhs, uint64_t rhs,
                                       uint32_t predicate, uint32_t outcome) {
    __fuzz_rt_record_cmp(barrier_id, lhs, rhs, predicate, outcome);
}
