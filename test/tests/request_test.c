#include <stdlib.h>
#include <check.h>

// Archivo testeado
#include "request/request.c"

uint8_t request_test_input_domain_success[] = {
    SOCKS_VERSION, REQUEST_COMMAND_CONNECT, 0x00, REQUEST_ADD_TYPE_DOMAIN_NAME,
    /* google.com */ 0x0a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    /* Port: 592 */ 0x02, 0x50,
};

// TODO: test IP4 success case and all error cases


START_TEST (request_test_core_success_feed) {

    uint8_t *input = request_test_input_domain_success;
    uint16_t port = 592;
    char domainName[] = "google.com";

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    ck_assert_uint_eq(p->addressLength, 0);

    ck_assert(p->currentState == REQUEST_VERSION);

    request_parser_feed(p, input[0]);

    ck_assert(p->currentState == REQUEST_COMMAND);

    request_parser_feed(p, input[1]);

    ck_assert(p->currentState == REQUEST_RESERVED);

    request_parser_feed(p, input[2]);

    ck_assert(p->currentState == REQUEST_ADD_TYPE);

    request_parser_feed(p, input[3]);

    ck_assert(p->currentState == REQUEST_DOMAIN_LENGTH);

    ck_assert_uint_eq(REQUEST_ADD_TYPE_DOMAIN_NAME, p->addressType);

    uint8_t domainNameLength = input[4];

    request_parser_feed(p, domainNameLength);

    ck_assert(p->currentState == REQUEST_ADDRESS);

    ck_assert_uint_eq(domainNameLength, p->addressLength);

    ck_assert_uint_eq(domainNameLength, p->addressRemaining);

    // Consuming Domain Name
    for(int i = 1; i < domainNameLength; i++) {

        uint8_t byte = input[4 + i];

        request_parser_feed(p, byte);

        ck_assert(p->currentState == REQUEST_ADDRESS);

        ck_assert_uint_eq(domainNameLength, p->addressLength);

        ck_assert_uint_eq(domainNameLength - i, p->addressRemaining);
    }

    // Last Domain Name Byte
    request_parser_feed(p, input[4 + domainNameLength]);

    ck_assert(p->currentState == REQUEST_PORT_HIGH);

    ck_assert_uint_eq(domainNameLength, p->addressLength);

    ck_assert_uint_eq(0, p->addressRemaining);

    ck_assert_str_eq((char*)p->address, domainName);

    ck_assert_int_eq(strlen(domainName), domainNameLength);

    ck_assert_int_eq(domainNameLength, strlen((char*)p->address));

    request_parser_feed(p, input[5 + domainNameLength]);

    ck_assert(p->currentState == REQUEST_PORT_LOW);

    ck_assert(!request_is_done(p->currentState, &errored));

    ck_assert(!errored);

    request_parser_feed(p, input[6 + domainNameLength]);

    ck_assert(p->currentState == REQUEST_SUCCESS);

    ck_assert_uint_eq(port, p->port);

    ck_assert(request_is_done(p->currentState, &errored));

    ck_assert(!errored);

}
END_TEST

START_TEST (request_test_core_success_consume) {

    uint8_t *input = request_test_input_domain_success;
    uint8_t inputLen = N(request_test_input_domain_success);
    uint16_t port = 592;
    char domainName[] = "google.com";

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, inputLen, input);
    buffer_write_adv(b, inputLen);

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    ck_assert_uint_eq(p->addressLength, 0);

    ck_assert(p->currentState == REQUEST_VERSION);

    enum RequestState state = request_parser_consume(b, p, &errored);

    ck_assert(!errored);

    // Final Parser Check
    ck_assert(p->currentState == REQUEST_SUCCESS);
    ck_assert(p->currentState == state);

    ck_assert_uint_eq(REQUEST_ADD_TYPE_DOMAIN_NAME, p->addressType);

    ck_assert_uint_eq(strlen(domainName), p->addressLength);

    ck_assert_uint_eq(0, p->addressRemaining);

    ck_assert_str_eq((char*)p->address, domainName);

    ck_assert_int_eq(strlen(domainName), strlen((char*)p->address));

    ck_assert_uint_eq(port, p->port);


    ck_assert(request_is_done(p->currentState, &errored));

    ck_assert(!errored);

}
END_TEST

Suite * request_test_suite(void) {
    Suite *s   = suite_create("request");

    TCase *tc  = tcase_create("core");
    tcase_add_test(tc, request_test_core_success_feed);
    tcase_add_test(tc, request_test_core_success_consume);
    suite_add_tcase(s, tc);

    return s;
}