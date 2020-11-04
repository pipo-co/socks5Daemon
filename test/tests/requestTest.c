#include <stdlib.h>
#include <check.h>

#include "states/request/request.c"

#define N(x) (sizeof(x)/sizeof((x)[0]))

uint8_t request_test_input_same_state[] = {
    0x05, 0x01, 0x00, 0x1,
};

uint8_t request_test_input_unsupported_address_type[] = {
    0x05, 0x01, 0x00, 0xFE,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};

uint8_t request_test_input_unsupported_version[] = {
    0x06, 0x01, 0x00, 0x01,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};

uint8_t request_test_input_unsupported_command[] = {
    0x05, 0x02, 0x00, 0x01,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};

uint8_t request_test_input_valid_ipv4[] = {
    0x05, 0x01, 0x00, 0x01,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50, 
};

uint8_t request_test_input_invalid_ipv4[] = {
    0x05, 0x01, 0x00, 0x01,
    /* 255.255.255.255 */ 0xff, 0xff, 0xff, 0xff,
    /* Port: 592 */ 0x02, 0x50, 
};

uint8_t request_test_input_valid_ipv6[] = {
    0x05, 0x01, 0x00, 0x01,
    /* 2001:0db8:85a3:0000:0000:8a2e:0370:7334 */ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
    /* Port: 592 */ 0x02, 0x50, 
};

uint8_t request_test_input_invalid_ipv6[] = {
    0x05, 0x01, 0x00, 0x01,
    /* 2001:0db8:85a3:0000:0000:8a2e:0370:7334 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    /* Port: 592 */ 0x02, 0x50, 
};


START_TEST (request_test_core_on_arrival) {

    SelectorEvent * key = malloc(sizeof(*key));

    SessionHandlerP socks5_p =  malloc(sizeof(*socks5_p));

    key->data = socks5_p;

    request_on_arrival(key);

    socks5_p = (SessionHandlerP) key->data;

    ck_assert_uint_eq(socks5_p->socksHeader.requestHeader.rep, SUCCESSFUL);

    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (request_test_core_on_read_same_state) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_same_state), request_test_input_same_state);
    buffer_write_adv(&socks5_p->input, N(request_test_input_same_state));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    key->data = socks5_p;

    unsigned state = request_on_read(key);

    free(key);
    free(socks5_p);

    ck_assert_uint_eq(state, REQUEST);
}
END_TEST

START_TEST (request_test_core_on_read_unsupported_address_type) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_unsupported_address_type), request_test_input_unsupported_address_type);
    buffer_write_adv(&socks5_p->input, N(request_test_input_unsupported_address_type));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    key->data = socks5_p;

    unsigned state = request_on_read(key);

    free(key);
    free(socks5_p);

    ck_assert_uint_eq(state, REQUEST_ERROR);
}
END_TEST

START_TEST (request_test_core_on_read_unsupported_version) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_unsupported_version), request_test_input_unsupported_version);
    buffer_write_adv(&socks5_p->input, N(request_test_input_unsupported_version));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    key->data = socks5_p;

    unsigned state = request_on_read(key);

    free(key);
    free(socks5_p);

    ck_assert_uint_eq(state, REQUEST_ERROR);
}
END_TEST

START_TEST (request_test_core_on_read_unsupported_command) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_unsupported_command), request_test_input_unsupported_command);
    buffer_write_adv(&socks5_p->input, N(request_test_input_unsupported_command));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    key->s = selector_new(8);
    

    const struct FdHandler socksv5 = {
        .handle_read       = NULL,//socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    selector_register(key->s, 1, &socksv5, OP_READ, NULL);
    
    key->data = socks5_p;

    unsigned state = request_on_read(key);

    selector_destroy(key->s);
    free(key);
    free(socks5_p);

    ck_assert_uint_eq(state, REQUEST_ERROR);
}
END_TEST

START_TEST (request_test_core_on_read_valid_ipv4) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_valid_ipv4), request_test_input_valid_ipv4);
    buffer_write_adv(&socks5_p->input, N(request_test_input_valid_ipv4));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    selector_init(&conf);

    FdSelector selector = selector_new(1024);

    const struct FdHandler socksv5 = {
        .handle_read       = NULL,//socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    selector_register(selector, server, &socksv5, OP_READ, NULL);

    key->s = selector;
    key->data = socks5_p;

    unsigned state = request_on_read(key);

    ck_assert_uint_eq(state, IP_CONNECT);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);    
}
END_TEST

START_TEST (request_test_core_on_read_invalid_ipv4) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_invalid_ipv4), request_test_input_invalid_ipv4);
    buffer_write_adv(&socks5_p->input, N(request_test_input_invalid_ipv4));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    selector_init(&conf);

    FdSelector selector = selector_new(1024);

    const struct FdHandler socksv5 = {
        .handle_read       = NULL,//socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    selector_register(selector, server, &socksv5, OP_READ, NULL);

    key->s = selector;
    key->data = socks5_p;

    unsigned state = request_on_read(key);

    ck_assert_uint_eq(state, REQUEST_ERROR);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);    
}
END_TEST

START_TEST (request_test_core_on_read_valid_ipv6) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_valid_ipv6), request_test_input_valid_ipv6);
    buffer_write_adv(&socks5_p->input, N(request_test_input_valid_ipv6));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    selector_init(&conf);

    FdSelector selector = selector_new(1024);

    const struct FdHandler socksv5 = {
        .handle_read       = NULL,//socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    selector_register(selector, server, &socksv5, OP_READ, NULL);

    key->s = selector;
    key->data = socks5_p;

    unsigned state = request_on_read(key);

    ck_assert_uint_eq(state, IP_CONNECT);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);    
}
END_TEST

START_TEST (request_test_core_on_read_invalid_ipv6) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST;
    socks5_p->sessionStateMachine = stm;

    buffer_init(&socks5_p->input, N(request_test_input_invalid_ipv4), request_test_input_invalid_ipv4);
    buffer_write_adv(&socks5_p->input, N(request_test_input_invalid_ipv4));

    RequestHeader requestHeader;
    memset(&requestHeader.parser, '\0', sizeof(requestHeader.parser));
    requestHeader.parser.currentState = REQUEST_PARSER_VERSION;
    
    socks5_p->socksHeader.requestHeader = requestHeader;

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    selector_init(&conf);

    FdSelector selector = selector_new(1024);

    const struct FdHandler socksv5 = {
        .handle_read       = NULL,//socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    selector_register(selector, server, &socksv5, OP_READ, NULL);

    key->s = selector;
    key->data = socks5_p;

    unsigned state = request_on_read(key);

    ck_assert_uint_eq(state, REQUEST_ERROR);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);    
}
END_TEST

Suite * request_test_suite(void) {

    Suite *s   = suite_create("request");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, request_test_core_on_arrival);
    tcase_add_test(tc, request_test_core_on_read_same_state);
    tcase_add_test(tc, request_test_core_on_read_unsupported_address_type);
    tcase_add_test(tc, request_test_core_on_read_unsupported_version);
    tcase_add_test(tc, request_test_core_on_read_unsupported_command);
    tcase_add_test(tc, request_test_core_on_read_valid_ipv4);
    tcase_add_test(tc, request_test_core_on_read_invalid_ipv4);
    tcase_add_test(tc, request_test_core_on_read_valid_ipv6);
    tcase_add_test(tc, request_test_core_on_read_invalid_ipv6);
    

    suite_add_tcase(s, tc);

    return s;
}