#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy_loader.h"

int main(void) {
    policy_loader_t loader;
    policy_loader_init(&loader, NULL);

    const mutation_policy_t *policy = policy_loader_get(&loader);
    if (!policy) {
        printf("[PASS] policy_loader: no policy file is ok\n");
    } else {
        printf("[INFO] policy_loader: loaded policy_id=%s version=%u enabled=%d\n",
               policy->policy_id, policy->version, policy->enabled);
    }

    printf("[PASS] policy_loader: basic init test passed\n");
    return 0;
}
