#ifndef ONLINE_CONTEXT_LOADER_H
#define ONLINE_CONTEXT_LOADER_H

#include <stdint.h>

#define ONLINE_CONTEXT_TRANSITION_ID_MAX 64
#define ONLINE_CONTEXT_PATH_MAX 512

typedef struct {
    char active_transition[ONLINE_CONTEXT_TRANSITION_ID_MAX];
    uint32_t version;
    uint32_t processed_sidecars;
    int loaded;
    int has_active_transition;
} online_context_t;

typedef struct {
    online_context_t context;
    uint32_t cached_version;
    char context_path[ONLINE_CONTEXT_PATH_MAX];
} online_context_loader_t;

void online_context_loader_init(online_context_loader_t *loader,
                                const char *context_path);
int online_context_loader_try_reload(online_context_loader_t *loader);
const online_context_t *online_context_loader_get(
    online_context_loader_t *loader);

#endif
