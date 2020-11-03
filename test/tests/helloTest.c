#include <stdlib.h>
#include <check.h>

// Archivo testeado
#include "states/hello/hello.c"

// enum HelloParserTestState {
//     HELLO_PARSER_VERSION,
//     HELLO_PARSER_NMETHODS,
//     HELLO_PARSER_METHODS,
//     HELLO_PARSER_DONE,
//     HELLO_PARSER_INVALID_STATE,
// };
uint8_t hello_test_state_not_changing[] = {
    0x05, 0x01
};

uint8_t hello_test_input_success[] = {
    0x05, 0x01, 0x02
};

uint8_t hello_test_input_unsupported_version[] = {
    0x06, 0x01, 0x00
};

uint8_t hello_test_input_no_acceptable_methods[] = {
    0x05, 0x01, 0x01
};

START_TEST (hello_test_core_on_auth_method) {
   
    HelloParser * p = calloc(sizeof(*p),1);

    uint8_t method = NO_ACCEPTABLE_METHODS;

    p->data = &method;
    
    on_auth_method(p, NO_AUTHENTICATION);

    ck_assert_uint_eq(*(uint8_t *)p->data, NO_AUTHENTICATION);

    on_auth_method(p, USER_PASSWORD);

    ck_assert_uint_eq(*(uint8_t *)p->data, USER_PASSWORD);

    on_auth_method(p, NO_AUTHENTICATION);

    ck_assert_uint_eq(*(uint8_t *)p->data, USER_PASSWORD);
    
    free(p);
}
END_TEST

START_TEST (hello_test_core_on_arrival) {

    SelectorEvent * key = malloc(sizeof(*key));

    SessionHandlerP socks5_p =  malloc(sizeof(*socks5_p));

    HelloHeader helloHeader;

    socks5_p->socksHeader.helloHeader = helloHeader;

    ClientInfo clientInfo;
    clientInfo.authMethod = NO_AUTHENTICATION;
    socks5_p->clientInfo = clientInfo;

    key->data = socks5_p;

    hello_on_arrival(key);

    socks5_p = (SessionHandlerP) key->data;

    ck_assert(socks5_p->socksHeader.helloHeader.bytes == 0);

    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (hello_test_core_on_post_read_same_state) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = HELLO;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(hello_test_state_not_changing), hello_test_state_not_changing);
    buffer_write_adv(&socks5_p->input, N(hello_test_state_not_changing));

    HelloHeader helloHeader;
    helloHeader.parser.current_state = HELLO_PARSER_VERSION;
    helloHeader.parser.on_auth_method = on_auth_method;
    helloHeader.parser.data = (uint8_t *) NO_ACCEPTABLE_METHODS;
    helloHeader.parser.methods_remaining = 0;

    socks5_p->socksHeader.helloHeader = helloHeader;

    key->data = socks5_p;

    unsigned state = hello_on_post_read(key);

    free(key);
    free(socks5_p);

    ck_assert_uint_eq(state, HELLO);
}
END_TEST

START_TEST (hello_test_core_on_post_read_success) {

    SelectorEvent *key = malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));
    
    SelectorStateMachine stm;
    stm.current = AUTH_METHOD_ANNOUNCEMENT;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(hello_test_input_success), hello_test_input_success);
    buffer_write_adv(&socks5_p->input, N(hello_test_input_success));

    HelloHeader helloHeader;
    helloHeader.parser.current_state = HELLO_PARSER_VERSION;
    helloHeader.parser.on_auth_method = on_auth_method;
    
    uint8_t method = NO_ACCEPTABLE_METHODS;
    helloHeader.parser.data = &method;
    helloHeader.parser.methods_remaining = 0;


    socks5_p->socksHeader.helloHeader = helloHeader;

    key->data = socks5_p;

    unsigned state = hello_on_post_read(key);

    ck_assert_uint_eq(state, AUTH_METHOD_ANNOUNCEMENT);

    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (hello_test_core_on_post_read_errored) {

    SelectorEvent *key = malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = HELLO;
    socks5_p->sessionStateMachine = stm;

    HelloHeader helloHeader;
    helloHeader.parser.current_state = HELLO_PARSER_INVALID_STATE;
    helloHeader.parser.on_auth_method = on_auth_method;
    
    uint8_t method = NO_ACCEPTABLE_METHODS;
    helloHeader.parser.data = &method;
    helloHeader.parser.methods_remaining = 0;


    socks5_p->socksHeader.helloHeader = helloHeader;

    key->data = socks5_p;

    unsigned state = hello_on_post_read(key);

    ck_assert_uint_eq(state, HELLO_ERROR);

    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (hello_test_core_on_post_read_unsupported_version) {

    SelectorEvent *key = malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));
    
    SelectorStateMachine stm;
    stm.current = HELLO;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(hello_test_input_unsupported_version), hello_test_input_unsupported_version);
    buffer_write_adv(&socks5_p->input, N(hello_test_input_unsupported_version));

    HelloHeader helloHeader;
    helloHeader.parser.current_state = HELLO_PARSER_VERSION;
    helloHeader.parser.on_auth_method = on_auth_method;
    
    uint8_t method = NO_ACCEPTABLE_METHODS;
    helloHeader.parser.data = &method;
    helloHeader.parser.methods_remaining = 0;


    socks5_p->socksHeader.helloHeader = helloHeader;

    key->data = socks5_p;

    unsigned state = hello_on_post_read(key);

    ck_assert_uint_eq(state, HELLO_ERROR);

    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (hello_test_core_on_post_read_errored_no_acceptable_methods) {

    SelectorEvent *key = malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));
    
    SelectorStateMachine stm;
    stm.current = HELLO;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(hello_test_input_no_acceptable_methods), hello_test_input_no_acceptable_methods);
    buffer_write_adv(&socks5_p->input, N(hello_test_input_no_acceptable_methods));

    HelloHeader helloHeader;
    helloHeader.parser.current_state = HELLO_PARSER_VERSION;
    helloHeader.parser.on_auth_method = on_auth_method;

    uint8_t method = NO_ACCEPTABLE_METHODS;
    helloHeader.parser.data = &method;
    helloHeader.parser.methods_remaining = 0;


    socks5_p->socksHeader.helloHeader = helloHeader;

    unsigned state = hello_on_post_read(key);

    ck_assert_uint_eq(state, HELLO_ERROR);

    free(key);
    free(socks5_p);

}
END_TEST


Suite * hello_test_suite(void) {
    Suite *s   = suite_create("hello");

    TCase *tc  = tcase_create("core");
    tcase_add_test(tc, hello_test_core_on_auth_method);
    tcase_add_test(tc, hello_test_core_on_arrival);
    tcase_add_test(tc, hello_test_core_on_post_read_same_state);
    tcase_add_test(tc, hello_test_core_on_post_read_success);
    tcase_add_test(tc, hello_test_core_on_post_read_errored);
    tcase_add_test(tc, hello_test_core_on_post_read_unsupported_version);
    tcase_add_test(tc, hello_test_core_on_post_read_errored_no_acceptable_methods);
    suite_add_tcase(s, tc);

    return s;
}