#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "reference/parser/parser.c"

// definición de maquina

enum states {
    S0,
    S1
};

enum event_type {
    FOO,
    BAR,
};

static void
foo(struct parser_event *ret, const uint8_t c) {
    ret->type    = FOO;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
bar(struct parser_event *ret, const uint8_t c) {
    ret->type    = BAR;
    ret->n       = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition ST_S0 [] =  {
    {.when = 'F',        .dest = S0,        .act1 = foo,},
    {.when = 'f',        .dest = S0,        .act1 = foo,},
    {.when = ANY,        .dest = S1,        .act1 = bar,},
};
static const struct parser_state_transition ST_S1 [] =  {
    {.when = 'F',        .dest = S0,        .act1 = foo,},
    {.when = 'f',        .dest = S0,        .act1 = foo,},
    {.when = ANY,        .dest = S1,        .act1 = bar,},
};

static const struct parser_state_transition *states [] = {
    ST_S0,
    ST_S1,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t states_n [] = {
    N(ST_S0),
    N(ST_S1),
};

static struct parser_definition definition = {
    .states_count = N(states),
    .states       = states,
    .states_n     = states_n,
    .start_state  = S0,
};

//// TEST

static void
parser_test_assert_eq(const unsigned type, const int c, const struct parser_event *e) {
    ck_assert_ptr_eq (0,    e->next);
    ck_assert_uint_eq(1,    e->n);
    ck_assert_uint_eq(type, e->type);
    ck_assert_uint_eq(c,    e->data[0]);

}

START_TEST (parser_test_basic) {
    struct parser *parser = parser_init(parser_no_classes(), &definition);
    parser_test_assert_eq(FOO,  'f', parser_feed(parser, 'f'));
    parser_test_assert_eq(FOO,  'F', parser_feed(parser, 'F'));
    parser_test_assert_eq(BAR,  'B', parser_feed(parser, 'B'));
    parser_test_assert_eq(BAR,  'b', parser_feed(parser, 'b'));

    parser_destroy(parser);
}
END_TEST

Suite *
parser_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("parser");

    tc = tcase_create("core");

    tcase_add_test(tc, parser_test_basic);
    suite_add_tcase(s, tc);

    return s;
}