#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser_utils.h"

const char *
parser_utils_strcmpi_event(const enum string_cmp_event_types type) {
    const char *ret;

    switch(type) {
        case STRING_CMP_MAYEQ:
            ret = "wait(c)";
            break;
        case STRING_CMP_EQ:
            ret = "eq(c)";
            break;
        case STRING_CMP_NEQ:
            ret = "neq(c)";
            break;
    }
    return ret;
}

static void
may_eq(struct parser_event *ret, const uint8_t c) {
    ret->type    = STRING_CMP_MAYEQ;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
eq(struct parser_event *ret, const uint8_t c) {
    ret->type    = STRING_CMP_EQ;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
neq(struct parser_event *ret, const uint8_t c) {
    ret->type    = STRING_CMP_NEQ;
    ret->n       = 1;
    ret->data[0] = c;
}

/*
 * para comparar "foo" (length 3) necesitamos 3 + 2 estados.
 * Los últimos dos, son el sumidero de comparación fallida, y
 * el estado donde se llegó a la comparación completa.
 *
 * static const struct parser_state_transition ST_0 [] =  {
 *   {.when = 'F',        .dest = 1,         .action1 = may_eq, },
 *   {.when = 'f',        .dest = 1,         .action1 = may_eq, },
 *   {.when = ANY,        .dest = NEQ,       .action1 = neq,},
 * };
 * static const struct parser_state_transition ST_1 [] =  {
 *   {.when = 'O',        .dest = 2,         .action1 = may_eq, },
 *   {.when = 'o',        .dest = 2,         .action1 = may_eq, },
 *   {.when = ANY,        .dest = NEQ,       .action1 = neq,},
 * };
 * static const struct parser_state_transition ST_2 [] =  {
 *   {.when = 'O',        .dest = EQ,        .action1 = eq, },
 *   {.when = 'o',        .dest = EQ,        .action1 = eq, },
 *   {.when = ANY,        .dest = NEQ,       .action1 = neq,},
 * };
 * static const struct parser_state_transition ST_EQ  (3) [] =  {
 *   {.when = ANY,        .dest = NEQ,       .action1 = neq,},
 * };
 * static const struct parser_state_transition ST_NEQ (4) [] =  {
 *   {.when = ANY,        .dest = NEQ,       .action1 = neq,},
 * };
 *
 */

struct parser_definition *parser_utils_strcmpi(struct parser_definition *pd, const char *s) {
    const size_t n = strlen(s);

    if(pd == NULL){   
        return NULL;
    }
    // struct parser_state_transition **states   = calloc(n + 2, sizeof(*states));
    // size_t *nstates                           = calloc(n + 2, sizeof(*nstates));
    // struct parser_state_transition *transitions= calloc(3 *(n + 2),
    //                                                     sizeof(*transitions));
    // if(states == NULL || nstates == NULL || transitions == NULL) {
    //     free(states);
    //     free(nstates);
    //     free(transitions);

    //     struct parser_definition def = {
    //         .start_state   = 0,
    //         .states_count  = 0,
    //         .states        = NULL,
    //         .states_n      = NULL,
    //     };
    //     return def;
    // }
    // estados fijos
    const size_t st_eq  = n;
    const size_t st_neq = n + 1;
    struct parser_state_transition states[MAX_STATES][TRANSITIONS_PER_STATE];
    size_t  nstates[MAX_STATES];


    for(size_t i = 0; i < n; i++) {

        const size_t dest = (i + 1 == n) ? st_eq : i + 1;

        states[i][0].when           = tolower(s[i]);
        states[i][0].dest           = dest;
        states[i][0].act1           = i + 1 == n ? eq : may_eq;
        states[i][1].when           = toupper(s[i]);
        states[i][1].dest           = dest;
        states[i][1].act1           = i + 1 == n ? eq : may_eq;
        states[i][2].when           = ANY;
        states[i][2].dest           = st_neq;
        states[i][2].act1           = neq;
        nstates[i]                  = 3;

        // transitions[i * 3 + 0].when = tolower(s[i]);
        // transitions[i * 3 + 0].dest = dest;
        // transitions[i * 3 + 0].act1 = i + 1 == n ? eq : may_eq;
        // transitions[i * 3 + 1].when = toupper(s[i]);
        // transitions[i * 3 + 1].dest = dest;
        // transitions[i * 3 + 1].act1 = i + 1 == n ? eq : may_eq;
        // transitions[i * 3 + 2].when = ANY;
        // transitions[i * 3 + 2].dest = st_neq;
        // transitions[i * 3 + 2].act1 = neq;
        // states     [i]              = transitions + (i * 3 + 0);
        // nstates    [i]              = 3;
    }
    // EQ
    
    states[n][0].when               = ANY;
    states[n][0].dest               = st_neq;
    states[n][0].act1               = neq;
    nstates[n]                      = 1;
    
    
    // transitions[(n + 0) * 3].when   = ANY;
    // transitions[(n + 0) * 3].dest   = st_neq;
    // transitions[(n + 0) * 3].act1   = neq;
    // states     [(n + 0)]            = transitions + ((n + 0) * 3 + 0);
    // nstates    [(n + 0)]            = 1;

    // NEQ
    states[n + 1][0].when               = ANY;
    states[n + 1][0].dest               = st_neq;
    states[n + 1][0].act1               = neq;
    nstates[n + 1]                      = 1;
    // transitions[(n + 1) * 3].when   = ANY;
    // transitions[(n + 1) * 3].dest   = st_neq;
    // transitions[(n + 1) * 3].act1   = neq;
    // states     [(n + 1)]            = transitions + ((n + 1) * 3 + 0);
    // nstates    [(n + 1)]            = 1;


    pd->start_state = 0;
    pd->states_count = n + 2;
    memcpy(&pd->states, &states, sizeof(states));
    memcpy(&pd->states_n, &nstates, sizeof(nstates));

    return pd;
}

void
parser_utils_strcmpi_destroy(const struct parser_definition *p) {
    free((void *)p->states[0]);
    free((void *)p->states);
    free((void *)p->states_n);
}
