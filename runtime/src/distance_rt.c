#include "fuzz_rt.h"
#include <stdint.h>

void __fuzz_rt_record_distance(uint32_t bb_id, uint32_t distance) {
    __fuzz_rt_record_bb(bb_id, distance);
}
