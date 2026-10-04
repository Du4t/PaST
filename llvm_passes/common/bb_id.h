#ifndef BB_ID_H
#define BB_ID_H

#include <stdint.h>

static uint32_t bb_id_counter = 0;

static uint32_t get_next_bb_id(void) {
    return __sync_fetch_and_add(&bb_id_counter, 1);
}

#endif
