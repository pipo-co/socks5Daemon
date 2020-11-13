#include "states/authSuccessful/authSuccessful.c"

#include <check.h>

START_TEST (auth_successful_test_core_request_marshall_incomplete) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(1*sizeof(*dummyBuffer));
    buffer_init(&buff, 1, dummyBuffer);
    size_t bytes = 0;

    auth_marshall(&buff, &bytes);

    ck_assert_uint_eq(bytes, 1);
    ck_assert_uint_eq(buffer_read(&buff), SOCKS_VERSION);

    free(dummyBuffer);
}
END_TEST

START_TEST (auth_successful_test_core_request_marshall_complete) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(3*sizeof(*dummyBuffer));
    buffer_init(&buff, 3, dummyBuffer);
    size_t bytes = 0;

    auth_marshall(&buff, &bytes);

    ck_assert_uint_eq(bytes, 2);
    ck_assert_uint_eq(buffer_read(&buff), SOCKS_VERSION);
    ck_assert_uint_eq(buffer_read(&buff), AUTH_SUCCESS_MESSAGE);
    
    
    free(dummyBuffer);
    
}
END_TEST



START_TEST (auth_successful_test_core_on_write_success) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = AUTH_SUCCESSFUL;
    socks5_p->sessionStateMachine = stm;

    AuthRequestHeader authRequestHeader;
    authRequestHeader.bytes = AUTH_REPLY_SIZE;
    
    socks5_p->socksHeader.authRequestHeader = authRequestHeader;

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

    unsigned state = auth_successful_on_write(key);

    ck_assert_uint_eq(state, REQUEST);

    selector_destroy(selector);
    free(key);
    free(socks5_p);

    
}
END_TEST

START_TEST (auth_successful_test_core_on_write_current) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = AUTH_SUCCESSFUL;
    socks5_p->sessionStateMachine = stm;

    AuthRequestHeader authRequestHeader;
    authRequestHeader.bytes = 1;
    
    socks5_p->socksHeader.authRequestHeader = authRequestHeader;

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

    unsigned state = auth_successful_on_write(key);

    ck_assert_uint_eq(state, AUTH_SUCCESSFUL);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);

    
}
END_TEST


Suite * auth_success_test_suite(void) {

    Suite *s   = suite_create("auth_successful");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, auth_successful_test_core_request_marshall_incomplete);
    tcase_add_test(tc, auth_successful_test_core_request_marshall_complete);
    tcase_add_test(tc, auth_successful_test_core_on_write_success);
    tcase_add_test(tc, auth_successful_test_core_on_write_current);
    

    suite_add_tcase(s, tc);

    return s;
}