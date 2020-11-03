#include <stdlib.h>
#include <check.h>

// Archivo testeado
#include "states/hello/helloParser.c"

// enum AuthMethodsTest {
//     NO_ACCEPTABLE_METHODS = 0xff, 
//     NO_AUTHENTICATION = 0x00, 
//     USER_PASSWORD = 0x02
//     }AuthMethodsTest;


uint8_t hello_parser_test_input_success[] = { 0x05, 0x02, 0x01, 0x00 };

uint8_t hello_parser_test_input_no_method[] = { 0x05, 0x00, 0x00 };

struct HelloParserTestMethods{
    uint8_t methodsReceived[2];
    uint8_t count;
};

bool hello_test_on_auth_method(HelloParser *p, uint8_t method) {
    struct HelloParserTestMethods *m = (struct HelloParserTestMethods *) p->data;
    m->methodsReceived[m->count++] = method;
    
    return true;
}  

void hello_test_init_parser(HelloParser *p, uint8_t *method) {
    struct HelloParserTestMethods *data = calloc(sizeof(*data), 1);
    hello_parser_init(p, hello_test_on_auth_method, data);

    p->on_auth_method = hello_test_on_auth_method;

    ck_assert_uint_eq(p->methods_remaining, 0);

    ck_assert(p->current_state == HELLO_PARSER_VERSION);
}

void hello_test_free_parser(HelloParser *p){
    free(p->data);
}

START_TEST (hello_parser_test_core_success_feed) {

    HelloParser parser;
    HelloParser *p = &parser;
    uint8_t method;
    bool errored;

     
    hello_test_init_parser(p, &method);

    hello_parser_feed(p, hello_parser_test_input_success[0]);

    ck_assert(p->current_state == HELLO_PARSER_NMETHODS);

    hello_parser_feed(p, hello_parser_test_input_success[1]);

    ck_assert(p->current_state == HELLO_PARSER_METHODS);

    ck_assert_uint_eq(p->methods_remaining, 2);

    hello_parser_feed(p, hello_parser_test_input_success[2]);

    ck_assert(p->current_state == HELLO_PARSER_METHODS);

    ck_assert_uint_eq(p->methods_remaining, 1);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->count, 1);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->methodsReceived[0], 0x01);

    ck_assert(!hello_parser_is_done(p->current_state, &errored));

    ck_assert(!errored);

    hello_parser_feed(p, hello_test_input_success[3]);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->count, 2);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->methodsReceived[1], 0x00);

    ck_assert(p->current_state == HELLO_PARSER_DONE);

    ck_assert_uint_eq(p->methods_remaining, 0);

    ck_assert(hello_parser_is_done(p->current_state, &errored));

    ck_assert(!errored);

    hello_test_free_parser(p);

}
END_TEST

START_TEST (hello_parser_test_core_success_consume) {

    HelloParser parser;
    HelloParser *p = &parser;

    uint8_t method;
    bool errored;

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, N(hello_parser_test_input_success), hello_parser_test_input_success);
    buffer_write_adv(b, N(hello_parser_test_input_success));
    
    hello_test_init_parser(p, &method);

    ck_assert(hello_parser_consume(b, p, &errored));

    ck_assert(!errored);

    ck_assert_uint_eq(p->methods_remaining, 0);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->count, 2);

    ck_assert(hello_parser_is_done(p->current_state, &errored));

    ck_assert(!errored);

    hello_test_free_parser(p);

}
END_TEST

START_TEST (hello_parser_test_core_no_method_feed) {

    HelloParser parser;
    HelloParser *p = &parser;
    uint8_t method;
    bool errored;

    hello_test_init_parser(p, &method);

    hello_parser_feed(p, hello_parser_test_input_no_method[0]);

    ck_assert(p->current_state == HELLO_PARSER_NMETHODS);

    hello_parser_feed(p, hello_parser_test_input_no_method[1]);

    ck_assert_uint_eq(p->methods_remaining, 0);
    
    ck_assert(p->current_state == HELLO_PARSER_DONE);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->count, 0);

    ck_assert(hello_parser_is_done(p->current_state, &errored));

    ck_assert(!errored);

    hello_test_free_parser(p);
}
END_TEST

START_TEST (hello_parser_test_core_no_method_consume) {

    HelloParser parser;
    HelloParser *p = &parser;

    uint8_t method;
    bool errored;

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, N(hello_parser_test_input_no_method), hello_parser_test_input_no_method);
    buffer_write_adv(b, N(hello_parser_test_input_no_method));

    
    hello_test_init_parser(p, &method);

    ck_assert(hello_parser_consume(b, p, &errored));

    ck_assert(!errored);

    ck_assert_uint_eq(p->methods_remaining, 0);

    ck_assert_uint_eq(((struct HelloParserTestMethods *)p->data)->count, 0);

    ck_assert(hello_parser_is_done(p->current_state, &errored));

    ck_assert(!errored);

    hello_test_free_parser(p);
}
END_TEST

Suite * hello_parser_test_suite(void) {
    Suite *s   = suite_create("helloParser");

    TCase *tc  = tcase_create("core");
    tcase_add_test(tc, hello_parser_test_core_success_feed);
    tcase_add_test(tc, hello_parser_test_core_success_consume);
    tcase_add_test(tc, hello_parser_test_core_no_method_feed);
    tcase_add_test(tc, hello_parser_test_core_no_method_consume);
    suite_add_tcase(s, tc);

    return s;
}