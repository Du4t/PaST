#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "online_context_loader.h"

static void skip_whitespace(const char **p) {
    while (**p && (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r'))
        (*p)++;
}

static int read_string(const char **p, char *out, size_t max_len) {
    skip_whitespace(p);
    if (**p != '"') return 0;
    (*p)++;
    size_t i = 0;
    while (**p && **p != '"' && i < max_len - 1) {
        if (**p == '\\') {
            (*p)++;
            if (!**p) return 0;
        }
        out[i++] = **p;
        (*p)++;
    }
    out[i] = '\0';
    if (**p == '"') (*p)++;
    return 1;
}

static int read_uint32(const char **p, uint32_t *out) {
    skip_whitespace(p);
    *out = 0;
    int found = 0;
    while (**p && **p >= '0' && **p <= '9') {
        *out = *out * 10 + (uint32_t)(**p - '0');
        (*p)++;
        found = 1;
    }
    return found;
}

static int skip_value(const char **p) {
    skip_whitespace(p);
    if (**p == '"') {
        (*p)++;
        while (**p && **p != '"') {
            if (**p == '\\') (*p)++;
            if (**p) (*p)++;
        }
        if (**p == '"') (*p)++;
        return 1;
    }
    if (**p == '{') {
        int depth = 1;
        (*p)++;
        while (**p && depth > 0) {
            if (**p == '{') depth++;
            else if (**p == '}') depth--;
            else if (**p == '"') {
                (*p)++;
                while (**p && **p != '"') {
                    if (**p == '\\') (*p)++;
                    if (**p) (*p)++;
                }
            }
            if (**p) (*p)++;
        }
        return 1;
    }
    if (**p == '[') {
        int depth = 1;
        (*p)++;
        while (**p && depth > 0) {
            if (**p == '[') depth++;
            else if (**p == ']') depth--;
            else if (**p == '"') {
                (*p)++;
                while (**p && **p != '"') {
                    if (**p == '\\') (*p)++;
                    if (**p) (*p)++;
                }
            }
            if (**p) (*p)++;
        }
        return 1;
    }
    if (**p == 't') { *p += 4; return 1; }
    if (**p == 'f') { *p += 5; return 1; }
    if (**p == 'n') { *p += 4; return 1; }
    if ((**p >= '0' && **p <= '9') || **p == '-') {
        char *end;
        strtod(*p, &end);
        *p = end;
        return 1;
    }
    return 0;
}

static int extract_online_context(const char *json, online_context_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    const char *p = json;

    skip_whitespace(&p);
    if (*p != '{') return 0;
    p++;

    while (*p) {
        skip_whitespace(&p);
        if (*p == '}') { p++; break; }
        if (*p == ',') { p++; continue; }

        char key[128] = {0};
        if (!read_string(&p, key, sizeof(key))) { skip_value(&p); continue; }
        skip_whitespace(&p);
        if (*p != ':') { skip_value(&p); continue; }
        p++;

        if (strcmp(key, "version") == 0) {
            read_uint32(&p, &ctx->version);
        } else if (strcmp(key, "version_number") == 0) {
            read_uint32(&p, &ctx->version);
        } else if (strcmp(key, "active_transition") == 0) {
            if (read_string(&p, ctx->active_transition,
                           sizeof(ctx->active_transition))) {
                ctx->has_active_transition = (
                    ctx->active_transition[0] != '\0');
            } else {
                skip_value(&p);
            }
        } else if (strcmp(key, "processed_sidecars") == 0) {
            read_uint32(&p, &ctx->processed_sidecars);
        } else {
            skip_value(&p);
        }
    }

    ctx->loaded = 1;
    return 1;
}

void online_context_loader_init(online_context_loader_t *loader,
                                const char *context_path) {
    memset(loader, 0, sizeof(*loader));
    if (context_path && context_path[0]) {
        strncpy(loader->context_path, context_path,
                sizeof(loader->context_path) - 1);
    } else {
        const char *env = getenv("FTFUZZ_ONLINE_CONTEXT");
        if (env) {
            strncpy(loader->context_path, env,
                    sizeof(loader->context_path) - 1);
        } else {
            strncpy(loader->context_path,
                    "/tmp/ftfuzz_online/online_transition_runtime_context.json",
                    sizeof(loader->context_path) - 1);
        }
    }
    online_context_loader_try_reload(loader);
}

int online_context_loader_try_reload(online_context_loader_t *loader) {
    FILE *fp = fopen(loader->context_path, "r");
    if (!fp) {
        loader->context.loaded = 0;
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 10 * 1024 * 1024) {
        fclose(fp);
        return 0;
    }

    char *json = (char *)malloc(fsize + 1);
    if (!json) {
        fclose(fp);
        return 0;
    }
    size_t nread = fread(json, 1, fsize, fp);
    json[nread] = '\0';
    fclose(fp);

    online_context_t new_ctx;
    if (!extract_online_context(json, &new_ctx)) {
        free(json);
        return 0;
    }
    free(json);

    if (!new_ctx.loaded) return 0;

    if (new_ctx.version != 0 &&
        new_ctx.version == loader->cached_version) {
        return 0;
    }

    if (loader->cached_version != 0 &&
        loader->context.has_active_transition &&
        new_ctx.has_active_transition &&
        strcmp(loader->context.active_transition,
               new_ctx.active_transition) != 0) {
        fprintf(stderr,
                "[FTFuzz] online context: active_transition changed: "
                "%s -> %s\n",
                loader->context.active_transition,
                new_ctx.active_transition);
    }

    loader->context = new_ctx;
    loader->cached_version = new_ctx.version;
    return 1;
}

const online_context_t *online_context_loader_get(
    online_context_loader_t *loader) {
    if (!loader->context.loaded) return NULL;
    return &loader->context;
}
