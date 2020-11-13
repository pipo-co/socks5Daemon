#include <stdio.h>
#include <stdlib.h>
#include <check.h>

// Archivo testeado
#include "reference/parser_utils/parser_utils.c"

START_TEST (parser_test_eq) {
    struct parser_definition pd;
    parser_utils_strcmpi(&pd, "foo");
    struct parser parser;
    parser_init(&parser, parser_no_classes(), & pd);
    struct parser_event *event = parser_feed(&parser, 'f');
    ck_assert_uint_eq(event->type, STRING_CMP_MAYEQ);
    event = parser_feed(&parser, 'o');
    ck_assert_uint_eq(event->type, STRING_CMP_MAYEQ);
    event = parser_feed(&parser, 'o');
    ck_assert_uint_eq(event->type, STRING_CMP_EQ);
}
END_TEST

START_TEST (parser_test_neq) {
    struct parser_definition pd;
    parser_utils_strcmpi(&pd, "foo");
    struct parser parser;
    parser_init(&parser, parser_no_classes(), & pd);
    struct parser_event *event = parser_feed(&parser, 'f');
    ck_assert_uint_eq(event->type, STRING_CMP_MAYEQ);
    event = parser_feed(&parser, 'o');
    ck_assert_uint_eq(event->type, STRING_CMP_MAYEQ);
    event = parser_feed(&parser, 'b');
    ck_assert_uint_eq(event->type, STRING_CMP_NEQ);
}
END_TEST

Suite *
parser_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("parser");

    tc = tcase_create("core");

    tcase_add_test(tc, parser_test_eq);
    tcase_add_test(tc, parser_test_neq);
    suite_add_tcase(s, tc);

    return s;
}

