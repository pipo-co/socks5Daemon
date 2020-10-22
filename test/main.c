// Main Application Test

#include <check.h>
#include <stdlib.h>

#define N(x) (sizeof(x)/sizeof((x)[0]))

typedef Suite *(*suiteSupplier)(void);

// Test files being exercised
#include "tests/buffer_test.c"
#include "tests/parser_test.c"
#include "tests/parser_utils_test.c"
#include "tests/hello_test.c"

// Tests being exercised
static const suiteSupplier suiteSuppliers[] = {
    buffer_test_suite,
    parser_test_suite,
    parser_utils_test_suite,
    hello_test_suite,
};

SRunner * test_srunner_init(void) {
    const int suiteCount = N(suiteSuppliers);

    SRunner *sr = srunner_create(suiteSuppliers[0]());

    for(int i = 1; i < suiteCount; i++)
        srunner_add_suite(sr, suiteSuppliers[i]());

    return sr;
}

int main(void) {

    SRunner *sr  = test_srunner_init();

    srunner_run_all(sr, CK_NORMAL);

    int number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}