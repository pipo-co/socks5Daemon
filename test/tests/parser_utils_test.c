#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "reference/parser_utils/parser_utils.c"

static void
parser_utils_test_assert_eq(const unsigned type, const int c, const struct parser_event *e) {
    ck_assert_ptr_eq (0,    e->next);
    ck_assert_uint_eq(1,    e->n);
    ck_assert_uint_eq(type, e->type);
    ck_assert_uint_eq(c,    e->data[0]);

}

START_TEST (parser_utils_test_eq) {
    const struct parser_definition d = parser_utils_strcmpi("foo");

    struct parser *parser = parser_init(parser_no_classes(), &d);
    parser_utils_test_assert_eq(STRING_CMP_MAYEQ,  'f', parser_feed(parser, 'f'));
    parser_utils_test_assert_eq(STRING_CMP_MAYEQ,  'O', parser_feed(parser, 'O'));
    parser_utils_test_assert_eq(STRING_CMP_EQ,     'o', parser_feed(parser, 'o'));
    parser_utils_test_assert_eq(STRING_CMP_NEQ,    'X', parser_feed(parser, 'X'));
    parser_utils_test_assert_eq(STRING_CMP_NEQ,    'y', parser_feed(parser, 'y'));

    parser_destroy(parser);
    parser_utils_strcmpi_destroy(&d);
}
END_TEST

Suite *
parser_utils_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("parser_utils");

    tc = tcase_create("core");

    tcase_add_test(tc, parser_utils_test_eq);
    suite_add_tcase(s, tc);

    return s;
}

