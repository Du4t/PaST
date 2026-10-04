#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "semantic_mutator.h"
#include "policy_loader.h"

#ifndef AFL_STATE_T_DEFINED
typedef void afl_state_t;
#endif

static semantic_mutator_t *g_mutator = NULL;

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    (void)afl;
    g_mutator = (semantic_mutator_t *)malloc(sizeof(semantic_mutator_t));
    if (!g_mutator) return NULL;

    const char *policy_path = getenv("FTFUZZ_POLICY_PATH");
    semantic_mutator_init(g_mutator, policy_path, seed);

    fprintf(stderr, "[ftfuzz] Custom mutator initialized, policy_path=%s, seed=%u\n",
            policy_path ? policy_path : "(default)", seed);

    return g_mutator;
}

size_t afl_custom_fuzz(void *data,
                       unsigned char *buf,
                       size_t buf_size,
                       unsigned char **out_buf,
                       unsigned char *add_buf,
                       size_t add_buf_size,
                       size_t max_size) {
    (void)add_buf;
    (void)add_buf_size;

    semantic_mutator_t *sm = (semantic_mutator_t *)data;
    if (!sm) {
        *out_buf = buf;
        return buf_size;
    }

    size_t out_size = semantic_mutator_fuzz(sm, buf, buf_size, out_buf, max_size);
    return out_size;
}

unsigned int afl_custom_fuzz_count(void *data,
                                    const unsigned char *buf,
                                    size_t buf_size) {
    (void)data;
    (void)buf;
    (void)buf_size;
    return 1;
}

void afl_custom_deinit(void *data) {
    semantic_mutator_t *sm = (semantic_mutator_t *)data;
    if (sm) {
        fprintf(stderr, "[ftfuzz] Mutator deinit: total=%u policy=%u fallback=%u\n",
                sm->total_mutations, sm->policy_mutations, sm->fallback_mutations);
        semantic_mutator_deinit(sm);
        free(sm);
    }
}
