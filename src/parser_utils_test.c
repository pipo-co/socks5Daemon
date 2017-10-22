#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "parser_utils.h"

static void
assert_eq(const unsigned type, const int c, const struct parser_event *e) {
    ck_assert_ptr_eq (0,    e->next);
    ck_assert_uint_eq(1,    e->n);
    ck_assert_uint_eq(type, e->type);
    ck_assert_uint_eq(c,    e->data[0]);

}

START_TEST (test_eq) {
    const struct parser_definition d = parser_utils_strcmpi("foo");

    struct parser *parser = parser_init(parser_no_classes(), &d);
    assert_eq(STRING_CMP_MAYEQ,  'f', parser_feed(parser, 'f'));
    assert_eq(STRING_CMP_MAYEQ,  'O', parser_feed(parser, 'O'));
    assert_eq(STRING_CMP_EQ,     'o', parser_feed(parser, 'o'));
    assert_eq(STRING_CMP_NEQ,    'X', parser_feed(parser, 'X'));
    assert_eq(STRING_CMP_NEQ,    'y', parser_feed(parser, 'y'));

    parser_destroy(parser);
    parser_utils_strcmpi_destroy(&d);
}
END_TEST

Suite *
suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("parser_utils");

    /* Core test case */
    tc = tcase_create("parser_utils");

    tcase_add_test(tc, test_eq);
    suite_add_tcase(s, tc);

    return s;
}



int
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

