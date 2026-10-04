#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t simple_rng(uint32_t *seed) {
    *seed = (*seed * 1103515245 + 12345) & 0x7fffffff;
    return *seed;
}

size_t fallback_mutation(unsigned char *buf, size_t buf_size,
                          size_t max_size, unsigned int *rng_seed) {
    if (buf_size == 0) return 0;

    uint32_t choice = simple_rng(rng_seed) % 5;
    switch (choice) {
        case 0: {
            uint32_t pos = simple_rng(rng_seed) % buf_size;
            buf[pos] ^= (1 << (simple_rng(rng_seed) % 8));
            break;
        }
        case 1: {
            uint32_t pos = simple_rng(rng_seed) % buf_size;
            buf[pos] = (unsigned char)(simple_rng(rng_seed) % 256);
            break;
        }
        case 2: {
            if (buf_size < max_size) {
                uint32_t pos = simple_rng(rng_seed) % (buf_size > 0 ? buf_size : 1);
                unsigned char byte = (unsigned char)(simple_rng(rng_seed) % 256);
                memmove(buf + pos + 1, buf + pos, buf_size - pos);
                buf[pos] = byte;
                buf_size++;
            }
            break;
        }
        case 3: {
            if (buf_size > 1) {
                uint32_t pos = simple_rng(rng_seed) % buf_size;
                memmove(buf + pos, buf + pos + 1, buf_size - pos - 1);
                buf_size--;
            }
            break;
        }
        case 4: {
            uint32_t pos1 = simple_rng(rng_seed) % buf_size;
            uint32_t pos2 = simple_rng(rng_seed) % buf_size;
            unsigned char tmp = buf[pos1];
            buf[pos1] = buf[pos2];
            buf[pos2] = tmp;
            break;
        }
    }

    return buf_size;
}
