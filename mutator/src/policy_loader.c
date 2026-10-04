#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "policy_loader.h"

static void skip_whitespace(const char **p) {
    while (**p && isspace((unsigned char)**p)) (*p)++;
}

static int expect_char(const char **p, char c) {
    skip_whitespace(p);
    if (**p != c) return 0;
    (*p)++;
    return 1;
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
    while (**p && isdigit((unsigned char)**p)) {
        *out = *out * 10 + (**p - '0');
        (*p)++;
        found = 1;
    }
    return found;
}

static int read_int(const char **p, int *out) {
    skip_whitespace(p);
    int sign = 1;
    if (**p == '-') { sign = -1; (*p)++; }
    else if (**p == '+') { (*p)++; }
    uint32_t v;
    if (!read_uint32(p, &v)) return 0;
    *out = sign * (int)v;
    return 1;
}

static int read_double(const char **p, double *out) {
    skip_whitespace(p);
    char *end;
    *out = strtod(*p, &end);
    if (end == *p) return 0;
    *p = end;
    return 1;
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
            (*p)++;
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
            (*p)++;
        }
        return 1;
    }
    if (**p == 't') { *p += 4; return 1; }
    if (**p == 'f') { *p += 5; return 1; }
    if (**p == 'n') { *p += 4; return 1; }
    if (isdigit((unsigned char)**p) || **p == '-') {
        char *end;
        strtod(*p, &end);
        *p = end;
        return 1;
    }
    return 0;
}

static int read_bool(const char **p, int *out) {
    skip_whitespace(p);
    if (strncmp(*p, "true", 4) == 0) { *out = 1; *p += 4; return 1; }
    if (strncmp(*p, "false", 5) == 0) { *out = 0; *p += 5; return 1; }
    return 0;
}

static void parse_hex_token(const char *hex, dict_token_t *token) {
    size_t hex_len = strlen(hex);
    token->len = 0;
    for (size_t i = 0; i + 1 < hex_len && token->len < MAX_TOKEN_BYTES; i += 2) {
        unsigned int byte_val;
        if (sscanf(hex + i, "%2x", &byte_val) == 1) {
            token->bytes[token->len++] = (uint8_t)byte_val;
        }
    }
}

static numeric_action_e parse_action(const char *s) {
    if (strcmp(s, "inc") == 0) return ACTION_INC;
    if (strcmp(s, "dec") == 0) return ACTION_DEC;
    if (strcmp(s, "random_delta") == 0) return ACTION_RANDOM_DELTA;
    if (strcmp(s, "boundary") == 0) return ACTION_BOUNDARY;
    if (strcmp(s, "fit_rhs") == 0) return ACTION_FIT_RHS;
    return ACTION_INC;
}

static int parse_policy_json(const char *json, mutation_policy_t *policy) {
    memset(policy, 0, sizeof(*policy));
    const char *p = json;

    if (!expect_char(&p, '{')) return 0;

    while (*p) {
        skip_whitespace(&p);
        if (*p == '}') break;
        if (*p == ',') { p++; continue; }

        char key[128] = {0};
        if (!read_string(&p, key, sizeof(key))) { skip_value(&p); continue; }
        if (!expect_char(&p, ':')) { skip_value(&p); continue; }

        if (strcmp(key, "policy_id") == 0) {
            read_string(&p, policy->policy_id, sizeof(policy->policy_id));
        } else if (strcmp(key, "version") == 0) {
            read_uint32(&p, &policy->version);
        } else if (strcmp(key, "enabled") == 0) {
            read_bool(&p, &policy->enabled);
        } else if (strcmp(key, "target_transition") == 0) {
            if (!expect_char(&p, '{')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == '}') { p++; break; }
                if (*p == ',') { p++; continue; }
                char tk[64] = {0};
                if (!read_string(&p, tk, sizeof(tk))) { skip_value(&p); continue; }
                if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                if (strcmp(tk, "transition_id") == 0) read_string(&p, policy->transition_id, sizeof(policy->transition_id));
                else if (strcmp(tk, "pre_state_id") == 0) read_string(&p, policy->pre_state_id, sizeof(policy->pre_state_id));
                else if (strcmp(tk, "post_state_id") == 0) read_string(&p, policy->post_state_id, sizeof(policy->post_state_id));
                else if (strcmp(tk, "barrier_id") == 0) read_string(&p, policy->barrier_id, sizeof(policy->barrier_id));
                else skip_value(&p);
            }
        } else if (strcmp(key, "activation") == 0) {
            if (!expect_char(&p, '{')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == '}') { p++; break; }
                if (*p == ',') { p++; continue; }
                char ak[64] = {0};
                if (!read_string(&p, ak, sizeof(ak))) { skip_value(&p); continue; }
                if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                if (strcmp(ak, "required_barrier_id") == 0) read_string(&p, policy->required_barrier_id, sizeof(policy->required_barrier_id));
                else if (strcmp(ak, "min_pre_hits") == 0) read_uint32(&p, &policy->min_pre_hits);
                else if (strcmp(ak, "max_stsr") == 0) read_double(&p, &policy->max_stsr);
                else if (strcmp(ak, "seed_state") == 0) read_string(&p, policy->seed_state, sizeof(policy->seed_state));
                else skip_value(&p);
            }
        } else if (strcmp(key, "preserve_ranges") == 0) {
            if (!expect_char(&p, '[')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == ']') { p++; break; }
                if (*p == ',') { p++; continue; }
                if (*p != '{') { skip_value(&p); continue; }
                if (policy->num_preserve_ranges >= MAX_PRESERVE_RANGES) { skip_value(&p); continue; }
                preserve_range_t *pr = &policy->preserve_ranges[policy->num_preserve_ranges];
                memset(pr, 0, sizeof(*pr));
                pr->weight = 0.9;
                expect_char(&p, '{');
                while (*p) {
                    skip_whitespace(&p);
                    if (*p == '}') { p++; break; }
                    if (*p == ',') { p++; continue; }
                    char rk[64] = {0};
                    if (!read_string(&p, rk, sizeof(rk))) { skip_value(&p); continue; }
                    if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                    if (strcmp(rk, "start") == 0) read_uint32(&p, &pr->start);
                    else if (strcmp(rk, "end") == 0) read_uint32(&p, &pr->end);
                    else if (strcmp(rk, "weight") == 0) read_double(&p, &pr->weight);
                    else if (strcmp(rk, "reason") == 0) read_string(&p, pr->reason, sizeof(pr->reason));
                    else skip_value(&p);
                }
                policy->num_preserve_ranges++;
            }
        } else if (strcmp(key, "focus_ranges") == 0) {
            if (!expect_char(&p, '[')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == ']') { p++; break; }
                if (*p == ',') { p++; continue; }
                if (*p != '{') { skip_value(&p); continue; }
                if (policy->num_focus_ranges >= MAX_FOCUS_RANGES) { skip_value(&p); continue; }
                focus_range_t *fr = &policy->focus_ranges[policy->num_focus_ranges];
                memset(fr, 0, sizeof(*fr));
                fr->weight = 0.5;
                expect_char(&p, '{');
                while (*p) {
                    skip_whitespace(&p);
                    if (*p == '}') { p++; break; }
                    if (*p == ',') { p++; continue; }
                    char rk[64] = {0};
                    if (!read_string(&p, rk, sizeof(rk))) { skip_value(&p); continue; }
                    if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                    if (strcmp(rk, "start") == 0) read_uint32(&p, &fr->start);
                    else if (strcmp(rk, "end") == 0) read_uint32(&p, &fr->end);
                    else if (strcmp(rk, "weight") == 0) read_double(&p, &fr->weight);
                    else if (strcmp(rk, "role") == 0) read_string(&p, fr->role, sizeof(fr->role));
                    else skip_value(&p);
                }
                policy->num_focus_ranges++;
            }
        } else if (strcmp(key, "numeric_fields") == 0) {
            if (!expect_char(&p, '[')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == ']') { p++; break; }
                if (*p == ',') { p++; continue; }
                if (*p != '{') { skip_value(&p); continue; }
                if (policy->num_numeric_fields >= MAX_NUMERIC_FIELDS) { skip_value(&p); continue; }
                numeric_field_t *nf = &policy->numeric_fields[policy->num_numeric_fields];
                memset(nf, 0, sizeof(*nf));
                nf->width = 4;
                strncpy(nf->endian, "big", sizeof(nf->endian));
                nf->confidence = 0.5;
                expect_char(&p, '{');
                while (*p) {
                    skip_whitespace(&p);
                    if (*p == '}') { p++; break; }
                    if (*p == ',') { p++; continue; }
                    char nk[64] = {0};
                    if (!read_string(&p, nk, sizeof(nk))) { skip_value(&p); continue; }
                    if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                    if (strcmp(nk, "start") == 0) read_uint32(&p, &nf->start);
                    else if (strcmp(nk, "end") == 0) read_uint32(&p, &nf->end);
                    else if (strcmp(nk, "width") == 0) read_uint32(&p, &nf->width);
                    else if (strcmp(nk, "endian") == 0) read_string(&p, nf->endian, sizeof(nf->endian));
                    else if (strcmp(nk, "signed") == 0) read_bool(&p, &nf->is_signed);
                    else if (strcmp(nk, "role") == 0) read_string(&p, nf->role, sizeof(nf->role));
                    else if (strcmp(nk, "confidence") == 0) read_double(&p, &nf->confidence);
                    else if (strcmp(nk, "actions") == 0) {
                        if (!expect_char(&p, '[')) { skip_value(&p); continue; }
                        nf->num_actions = 0;
                        while (*p) {
                            skip_whitespace(&p);
                            if (*p == ']') { p++; break; }
                            if (*p == ',') { p++; continue; }
                            char act[32] = {0};
                            if (read_string(&p, act, sizeof(act)) && nf->num_actions < MAX_ACTIONS) {
                                nf->actions[nf->num_actions++] = parse_action(act);
                            }
                        }
                    }
                    else skip_value(&p);
                }
                policy->num_numeric_fields++;
            }
        } else if (strcmp(key, "dictionary_tokens") == 0) {
            if (!expect_char(&p, '[')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == ']') { p++; break; }
                if (*p == ',') { p++; continue; }
                if (*p != '{') { skip_value(&p); continue; }
                if (policy->num_dict_tokens >= MAX_DICT_TOKENS) { skip_value(&p); continue; }
                dict_token_t *dt = &policy->dict_tokens[policy->num_dict_tokens];
                memset(dt, 0, sizeof(*dt));
                dt->weight = 0.5;
                expect_char(&p, '{');
                while (*p) {
                    skip_whitespace(&p);
                    if (*p == '}') { p++; break; }
                    if (*p == ',') { p++; continue; }
                    char dk[64] = {0};
                    if (!read_string(&p, dk, sizeof(dk))) { skip_value(&p); continue; }
                    if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                    if (strcmp(dk, "token_hex") == 0) {
                        char hex[256] = {0};
                        if (read_string(&p, hex, sizeof(hex))) {
                            parse_hex_token(hex, dt);
                        }
                    }
                    else if (strcmp(dk, "weight") == 0) read_double(&p, &dt->weight);
                    else if (strcmp(dk, "reason") == 0) read_string(&p, dt->reason, sizeof(dt->reason));
                    else skip_value(&p);
                }
                policy->num_dict_tokens++;
            }
        } else if (strcmp(key, "operator_weights") == 0) {
            if (!expect_char(&p, '{')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == '}') { p++; break; }
                if (*p == ',') { p++; continue; }
                char wk[64] = {0};
                if (!read_string(&p, wk, sizeof(wk))) { skip_value(&p); continue; }
                if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                if (strcmp(wk, "numeric_boundary") == 0) read_double(&p, &policy->op_weights.numeric_boundary);
                else if (strcmp(wk, "directional_arithmetic") == 0) read_double(&p, &policy->op_weights.directional_arithmetic);
                else if (strcmp(wk, "byte_pattern_insert") == 0) read_double(&p, &policy->op_weights.byte_pattern_insert);
                else if (strcmp(wk, "repair") == 0) read_double(&p, &policy->op_weights.repair);
                else if (strcmp(wk, "fallback") == 0) read_double(&p, &policy->op_weights.fallback);
                else skip_value(&p);
            }
        } else if (strcmp(key, "repair_rules") == 0) {
            if (!expect_char(&p, '[')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == ']') { p++; break; }
                if (*p == ',') { p++; continue; }
                if (*p != '{') { skip_value(&p); continue; }
                if (policy->num_repair_rules >= MAX_REPAIR_RULES) { skip_value(&p); continue; }
                repair_rule_t *rr = &policy->repair_rules[policy->num_repair_rules];
                memset(rr, 0, sizeof(*rr));
                strncpy(rr->endian, "big", sizeof(rr->endian));
                expect_char(&p, '{');
                while (*p) {
                    skip_whitespace(&p);
                    if (*p == '}') { p++; break; }
                    if (*p == ',') { p++; continue; }
                    char rrk[64] = {0};
                    if (!read_string(&p, rrk, sizeof(rrk))) { skip_value(&p); continue; }
                    if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                    if (strcmp(rrk, "type") == 0) {
                        char rtype[64] = {0};
                        if (read_string(&p, rtype, sizeof(rtype))) {
                            if (strcmp(rtype, "length_recompute") == 0) rr->type = REPAIR_LENGTH_RECOMPUTE;
                            else if (strcmp(rtype, "payload_size_fit") == 0) rr->type = REPAIR_PAYLOAD_SIZE_FIT;
                            else rr->type = REPAIR_CHECKSUM_NOOP;
                        }
                    }
                    else if (strcmp(rrk, "length_range") == 0) {
                        expect_char(&p, '[');
                        read_uint32(&p, &rr->length_start);
                        expect_char(&p, ',');
                        read_uint32(&p, &rr->length_end);
                        expect_char(&p, ']');
                    }
                    else if (strcmp(rrk, "payload_range") == 0) {
                        expect_char(&p, '[');
                        read_uint32(&p, &rr->payload_start);
                        expect_char(&p, ',');
                        read_uint32(&p, &rr->payload_end);
                        expect_char(&p, ']');
                    }
                    else if (strcmp(rrk, "endian") == 0) read_string(&p, rr->endian, sizeof(rr->endian));
                    else skip_value(&p);
                }
                policy->num_repair_rules++;
            }
        } else if (strcmp(key, "validation") == 0) {
            if (!expect_char(&p, '{')) { skip_value(&p); continue; }
            while (*p) {
                skip_whitespace(&p);
                if (*p == '}') { p++; break; }
                if (*p == ',') { p++; continue; }
                char vk[64] = {0};
                if (!read_string(&p, vk, sizeof(vk))) { skip_value(&p); continue; }
                if (!expect_char(&p, ':')) { skip_value(&p); continue; }
                if (strcmp(vk, "max_trials") == 0) read_uint32(&p, &policy->max_trials);
                else if (strcmp(vk, "downgrade_on_no_gain") == 0) read_bool(&p, &policy->downgrade_on_no_gain);
                else skip_value(&p);
            }
        } else {
            skip_value(&p);
        }
    }
    return 1;
}

void policy_loader_init(policy_loader_t *loader, const char *policy_path) {
    memset(loader, 0, sizeof(*loader));
    if (policy_path) {
        strncpy(loader->policy_path, policy_path, sizeof(loader->policy_path) - 1);
    } else {
        const char *env_path = getenv("FTFUZZ_POLICY_PATH");
        if (env_path) {
            strncpy(loader->policy_path, env_path, sizeof(loader->policy_path) - 1);
        } else {
            strncpy(loader->policy_path, "/tmp/ftfuzz_policies/current_policy.json",
                    sizeof(loader->policy_path) - 1);
        }
    }
    policy_loader_try_reload(loader);
}

int policy_loader_try_reload(policy_loader_t *loader) {
    FILE *fp = fopen(loader->policy_path, "r");
    if (!fp) {
        loader->loaded = 0;
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(fp);
        return 0;
    }

    char *json = (char *)malloc(fsize + 1);
    if (!json) {
        fclose(fp);
        return 0;
    }
    fread(json, 1, fsize, fp);
    json[fsize] = '\0';
    fclose(fp);

    mutation_policy_t new_policy;
    if (!parse_policy_json(json, &new_policy)) {
        free(json);
        return 0;
    }
    free(json);

    if (new_policy.version != 0 && new_policy.version == loader->cached_version) {
        return 0;
    }

    loader->policy = new_policy;
    loader->cached_version = new_policy.version;
    loader->loaded = 1;
    return 1;
}

const mutation_policy_t *policy_loader_get(policy_loader_t *loader) {
    if (!loader->loaded) return NULL;
    return &loader->policy;
}
