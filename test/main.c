// Main Application Test

#include <check.h>
#include <stdlib.h>

#define N(x) (sizeof(x)/sizeof((x)[0]))

typedef Suite *(*suiteSupplier)(void);

// Test files being exercised
#include "tests/buffer_test.c"
#include "tests/parser_test.c"
#include "tests/selector_test.c"
#include "tests/parser_utils_test.c"
#include "tests/netutils_test.c"
#include "tests/helloParserTest.c"
#include "tests/helloTest.c"
#include "tests/helloErrorTest.c"
#include "tests/authMethodAnnouncementTest.c"
#include "tests/authRequestTest.c"
#include "tests/authRequestParserTest.c"
#include "tests/authErrorTest.c"
#include "tests/authSuccessfulTest.c"
#include "tests/requestParserTest.c"
#include "tests/requestTest.c"
#include "tests/requestErrorTest.c"
#include "tests/ipConnectTest.c"
#include "tests/requestSuccessfulTest.c"
#include "tests/forwardingTest.c"
#include "tests/flushCloserTest.c"
#include "tests/flushClosyTest.c"
#include "tests/socks5Test.c"
#include "tests/stateMachineTest.c"
#include "tests/stateMachineBuilderTest.c"
#include "tests/dnsParserTest.c"
#include "tests/responseDnsTest.c"
#include "tests/generateDnsQueryTest.c"
#include "tests/dohBuilderTest.c"
#include "tests/httpDnsParserTest.c"
#include "tests/argsHandlerTest.c"
#include "tests/userHandlerTest.c"
#include "tests/statisticsTest.c"
#include "tests/base64Test.c"


// Tests being exercised
static const suiteSupplier suiteSuppliers[] = {
    buffer_test_suite,
    parser_test_suite,
    parser_utils_test_suite,
    hello_test_suite,
    hello_parser_test_suite,
    hello_error_test_suite,
    auth_method_announcement_test_suite,
    auth_success_test_suite,
    auth_error_test_suite,
    selector_test_suite,
    request_parser_test_suite,
    request_test_suite,
    request_success_test_suite,
    request_error_test_suite,
    forwarding_test_suite,
    flush_closer_test_suite,
    flush_closy_test_suite,
    response_dns_parser_test_suite,
    http_dns_parser_test_suite,
    base64_test_suite,
    doh_builder_test_suite,
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