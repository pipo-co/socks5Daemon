#include <stdlib.h>
#include <check.h>
#include <arpa/inet.h>

// Archivo testeado
#include "parsers/request/requestParser.c"

uint8_t request_parser_test_input_domain_success[] = {
    SOCKS_VERSION, REQUEST_PARSER_COMMAND_CONNECT, 0x00, REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME,
    /* google.com */ 0x0a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    /* Port: 592 */ 0x02, 0x50,
};

uint8_t request_parser_test_input_ipv4_success[] = {
    SOCKS_VERSION, REQUEST_PARSER_COMMAND_CONNECT, 0x00, REQUEST_PARSER_ADD_TYPE_IP4,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};

uint8_t request_parser_test_input_ipv6_success[] = {
    SOCKS_VERSION, REQUEST_PARSER_COMMAND_CONNECT, 0x00, REQUEST_PARSER_ADD_TYPE_IP6,
    /*2800:3f0:4002:809::200e*/ 0x28, 0x00, 0x03, 0xf0, 0x40, 0x02, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};

uint8_t request_parser_test_input_unsupported_address_type[] = {
    SOCKS_VERSION, REQUEST_PARSER_COMMAND_CONNECT, 0x00, 0xFE,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};


// TODO: test IP4 success case and all error cases


START_TEST (request_parser_test_domain_name_feed) {

    uint8_t *input = request_parser_test_input_domain_success;
    uint16_t port = 592;
    char domainName[] = "google.com";

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    ck_assert_uint_eq(p->addressLength, 0);

    ck_assert_uint_eq(REQUEST_PARSER_VERSION, p->currentState);

    request_parser_feed(p, input[0]);

    ck_assert_uint_eq(REQUEST_PARSER_COMMAND, p->currentState);

    request_parser_feed(p, input[1]);

    ck_assert_uint_eq(REQUEST_PARSER_RESERVED, p->currentState);

    request_parser_feed(p, input[2]);

    ck_assert_uint_eq(REQUEST_PARSER_ADD_TYPE, p->currentState);

    request_parser_feed(p, input[3]);

    ck_assert_uint_eq(REQUEST_PARSER_DOMAIN_LENGTH, p->currentState);

    ck_assert_uint_eq(SOCKS_5_ADD_TYPE_DOMAIN_NAME, p->addressType);

    uint8_t domainNameLength = input[4];

    request_parser_feed(p, domainNameLength);

    ck_assert_uint_eq(REQUEST_PARSER_DOMAIN_ADDRESS, p->currentState);

    ck_assert_uint_eq(domainNameLength, p->addressLength);

    ck_assert_uint_eq(domainNameLength, p->addressRemaining);

    // Consuming Domain Name
    for(int i = 1; i < domainNameLength; i++) {

        uint8_t byte = input[4 + i];

        request_parser_feed(p, byte);

        ck_assert(p->currentState == REQUEST_PARSER_DOMAIN_ADDRESS);

        ck_assert_uint_eq(domainNameLength, p->addressLength);

        ck_assert_uint_eq(domainNameLength - i, p->addressRemaining);
    }

    // Last Domain Name Byte
    request_parser_feed(p, input[4 + domainNameLength]);

    ck_assert_uint_eq(REQUEST_PARSER_PORT_HIGH, p->currentState);

    ck_assert_uint_eq(domainNameLength, p->addressLength);

    ck_assert_uint_eq(0, p->addressRemaining);

    ck_assert_str_eq((char*)p->address.domainName, domainName);

    ck_assert_int_eq(strlen(domainName), domainNameLength);

    ck_assert_int_eq(domainNameLength, strlen((char*)p->address.domainName));

    request_parser_feed(p, input[5 + domainNameLength]);

    ck_assert(p->currentState == REQUEST_PARSER_PORT_LOW);

    ck_assert(!request_parser_is_done(p->currentState, &errored));

    ck_assert(!errored);

    request_parser_feed(p, input[6 + domainNameLength]);

    ck_assert(p->currentState == REQUEST_PARSER_DONE);

    ck_assert_uint_eq(port, ntohs(p->port));

    ck_assert(request_parser_is_done(p->currentState, &errored));

    ck_assert(!errored);

}
END_TEST

START_TEST (request_parser_test_domain_name_consume) {

    uint8_t *input = request_parser_test_input_domain_success;
    uint8_t inputLen = N(request_parser_test_input_domain_success);
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

    ck_assert_uint_eq(REQUEST_PARSER_VERSION, p->currentState);

    ck_assert(request_parser_consume(b, p, &errored));

    ck_assert(!errored);

    // Final Parser Check
    ck_assert_uint_eq(SOCKS_5_ADD_TYPE_DOMAIN_NAME, p->addressType);

    ck_assert_uint_eq(strlen(domainName), p->addressLength);

    ck_assert_uint_eq(0, p->addressRemaining);

    ck_assert_str_eq((char*)p->address.domainName, domainName);

    ck_assert_int_eq(strlen(domainName), strlen((char*)p->address.domainName));

    ck_assert_uint_eq(port, ntohs(p->port));
}
END_TEST

START_TEST (request_parser_test_ipv4_consume) {

    uint8_t *input = request_parser_test_input_ipv4_success;
    uint8_t inputLen = N(request_parser_test_input_ipv4_success);
    uint16_t port = 592;
    char ipv4[] = "172.217.173.14";
    char ipvbuffer[INET_ADDRSTRLEN];

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, inputLen, input);
    buffer_write_adv(b, inputLen);

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    ck_assert_uint_eq(REQUEST_PARSER_VERSION, p->currentState);

    ck_assert(request_parser_consume(b, p, &errored));

    ck_assert(!errored);

    // Final Parser Check
    ck_assert_uint_eq(REQUEST_PARSER_COMMAND_CONNECT, p->cmd);

    ck_assert_uint_eq(SOCKS_VERSION, p->version);

    ck_assert_uint_eq(SOCKS_5_ADD_TYPE_IP4, p->addressType);

    ck_assert_uint_eq(0, p->addressRemaining);

    ck_assert_str_eq(inet_ntop(AF_INET, &p->address.ipv4, ipvbuffer, INET_ADDRSTRLEN), ipv4);

    ck_assert_uint_eq(port, ntohs(p->port));

}
END_TEST

START_TEST (request_parser_test_ipv6_consume) {

    uint8_t *input = request_parser_test_input_ipv6_success;
    uint8_t inputLen = N(request_parser_test_input_ipv6_success);
    uint16_t port = 592;
    char ipv6[] = "2800:3f0:4002:809::200e";
    char ipvbuffer[INET6_ADDRSTRLEN];

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, inputLen, input);
    buffer_write_adv(b, inputLen);

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    ck_assert_uint_eq(REQUEST_PARSER_VERSION, p->currentState);

    ck_assert(request_parser_consume(b, p, &errored));

    ck_assert(!errored);

    // Final Parser Check

    ck_assert_uint_eq(SOCKS_5_ADD_TYPE_IP6, p->addressType);

    ck_assert_uint_eq(REQUEST_PARSER_COMMAND_CONNECT, p->cmd);

    ck_assert_uint_eq(SOCKS_VERSION, p->version);

    ck_assert_uint_eq(0, p->addressRemaining);

    ck_assert_str_eq(inet_ntop(AF_INET6, &p->address.ipv6, ipvbuffer, INET6_ADDRSTRLEN), ipv6);

    ck_assert_uint_eq(port, ntohs(p->port));

}
END_TEST

START_TEST (request_parser_test_unsupported_address_type) {

    uint8_t *input = request_parser_test_input_unsupported_address_type;
    uint8_t inputLen = N(request_parser_test_input_unsupported_address_type);

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, inputLen, input);
    buffer_write_adv(b, inputLen);

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    ck_assert_uint_eq(REQUEST_PARSER_VERSION, p->currentState);

    ck_assert(request_parser_consume(b, p, &errored));

    ck_assert(errored);
    
    ck_assert_uint_eq(REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE, p->currentState);
}
END_TEST

START_TEST (request_parser_test_invalid_state) {

    uint8_t *input = request_parser_test_input_unsupported_address_type;
    uint8_t inputLen = N(request_parser_test_input_unsupported_address_type);

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, inputLen, input);
    buffer_write_adv(b, inputLen);

    RequestParser parser;
    RequestParser *p = &parser;
    bool errored;

    request_parser_init(p);

    p->currentState = 0xFE;

    ck_assert(request_parser_consume(b, p, &errored));

    ck_assert(errored);
}
END_TEST

Suite * request_parser_test_suite(void) {

    Suite *s   = suite_create("request_parser");
    TCase *success  = tcase_create("success");

    tcase_add_test(success, request_parser_test_domain_name_feed);
    tcase_add_test(success, request_parser_test_domain_name_consume);
    tcase_add_test(success, request_parser_test_ipv4_consume);
    tcase_add_test(success, request_parser_test_ipv6_consume);

    TCase *error  = tcase_create("error");
    tcase_add_test(error, request_parser_test_unsupported_address_type);
    tcase_add_test(error, request_parser_test_invalid_state);
    suite_add_tcase(s, success);
    suite_add_tcase(s, error);

    return s;
}