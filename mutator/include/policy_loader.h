#ifndef POLICY_LOADER_H
#define POLICY_LOADER_H

#include "mutation_policy.h"

typedef struct {
    mutation_policy_t policy;
    uint32_t cached_version;
    int loaded;
    char policy_path[512];
} policy_loader_t;

void policy_loader_init(policy_loader_t *loader, const char *policy_path);
int policy_loader_try_reload(policy_loader_t *loader);
const mutation_policy_t *policy_loader_get(policy_loader_t *loader);

#endif
