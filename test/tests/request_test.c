#include <stdlib.h>
#include <check.h>

// Archivo testeado
#include "request/request.c"

const uint8_t request_test_input_success[] = {
    0x05, 0x01, 0x00, 0x03, 0x0a, 0x67, 0x6f, 0x6f, 
    0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 
    0x50
};

// void hello_test_init_parser(HelloParser *p, uint8_t *method) {
//     hello_parser_init(p);
//     *method = NO_ACCEPTABLE_METHODS;
//     p->data = method;
//     p->on_auth_method = hello_test_on_auth_method;

//     ck_assert_uint_eq(p->methods_remaining, 0);

//     ck_assert(p->current_state == HELLO_VERSION);
// }


START_TEST (request_test_core_success_feed) {

    // HelloParser parser;
    // HelloParser *p = &parser;
    // uint8_t method;
    // bool errored;
    
    // hello_test_init_parser(p, &method);

    // hello_parser_feed(p, hello_test_input_success[0]);

    // ck_assert(p->current_state == HELLO_NMETHODS);

    // hello_parser_feed(p, hello_test_input_success[1]);

    // ck_assert(p->current_state == HELLO_METHODS);

    // ck_assert_uint_eq(p->methods_remaining, 2);

    // hello_parser_feed(p, hello_test_input_success[2]);

    // ck_assert(p->current_state == HELLO_METHODS);

    // ck_assert_uint_eq(p->methods_remaining, 1);

    // ck_assert_uint_eq(*(uint8_t*)p->data, NO_ACCEPTABLE_METHODS);

    // ck_assert(!hello_is_done(p->current_state, &errored));

    // ck_assert(!errored);

    // hello_parser_feed(p, hello_test_input_success[3]);

    // ck_assert(p->current_state == HELLO_DONE);

    // ck_assert_uint_eq(p->methods_remaining, 0);

    // ck_assert_uint_eq(*(uint8_t*)p->data, NO_AUTHENTICATION);

    // ck_assert(hello_is_done(p->current_state, &errored));

    // ck_assert(!errored);

}
END_TEST

START_TEST (request_test_core_success_consume) {

    // HelloParser parser;
    // HelloParser *p = &parser;

    // uint8_t method;
    // bool errored;

    // Buffer buffer;
    // Buffer *b = &buffer;

    // buffer_init(b, N(hello_test_input_success), hello_test_input_success);
    // buffer_write_adv(b, N(hello_test_input_success));

    
    // hello_test_init_parser(p, &method);

    // enum HelloState state = hello_parser_consume(b, p, &errored);

    // ck_assert(!errored);

    // ck_assert(p->current_state == HELLO_DONE);
    // ck_assert(p->current_state == state);

    // ck_assert_uint_eq(p->methods_remaining, 0);

    // ck_assert_uint_eq(*(uint8_t*)p->data, NO_AUTHENTICATION);

    // ck_assert(hello_is_done(p->current_state, &errored));

    // ck_assert(!errored);

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