#include "states/authMethodAnnouncement/authMethodAnnouncement.c"

START_TEST (auth_method_announcement_test_core_request_marshall_incomplete) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(1*sizeof(*dummyBuffer));
    buffer_init(&buff, 1, dummyBuffer);
    size_t bytes = 0;

    hello_marshall(&buff, &bytes, NO_AUTHENTICATION);

    ck_assert_uint_eq(bytes, 1);
    ck_assert_uint_eq(buffer_read(&buff), SOCKS_VERSION);

    free(dummyBuffer);
}
END_TEST

START_TEST (auth_method_announcement_test_core_request_marshall_complete) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(3*sizeof(*dummyBuffer));
    buffer_init(&buff, 3, dummyBuffer);
    size_t bytes = 0;

    hello_marshall(&buff, &bytes, NO_AUTHENTICATION);

    ck_assert_uint_eq(bytes, 2);
    ck_assert_uint_eq(buffer_read(&buff), SOCKS_VERSION);
    ck_assert_uint_eq(buffer_read(&buff), NO_AUTHENTICATION);
    
    
    free(dummyBuffer);
    
}
END_TEST


START_TEST (auth_method_announcement_test_core_on_write_success_no_authentication) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = AUTH_METHOD_ANNOUNCEMENT;
    socks5_p->sessionStateMachine = stm;

    HelloHeader helloHeader;
    helloHeader.bytes = HELLO_REPLY_SIZE;

    socks5_p->clientInfo.authMethod = NO_AUTHENTICATION;
    
    socks5_p->socksHeader.helloHeader = helloHeader;

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

    unsigned state = method_announcement_on_write(key);

    ck_assert_uint_eq(state, REQUEST);

    selector_destroy(selector);
    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (auth_method_announcement_test_core_on_write_success_authentication) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = AUTH_METHOD_ANNOUNCEMENT;
    socks5_p->sessionStateMachine = stm;

    HelloHeader helloHeader;
    helloHeader.bytes = HELLO_REPLY_SIZE;

    socks5_p->clientInfo.authMethod = USER_PASSWORD;
    
    socks5_p->socksHeader.helloHeader = helloHeader;

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

    unsigned state = method_announcement_on_write(key);

    ck_assert_uint_eq(state, AUTH_REQUEST);

    selector_destroy(selector);
    free(key);
    free(socks5_p);

}
END_TEST

START_TEST (auth_method_announcement_test_core_on_write_current) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = AUTH_METHOD_ANNOUNCEMENT;
    socks5_p->sessionStateMachine = stm;

    HelloHeader helloHeader;
    helloHeader.bytes = 1;
    
    socks5_p->socksHeader.helloHeader = helloHeader;

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

    unsigned state = method_announcement_on_write(key);

    ck_assert_uint_eq(state, AUTH_METHOD_ANNOUNCEMENT);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);

    
}
END_TEST


Suite * auth_method_announcement_test_suite(void) {

    Suite *s   = suite_create("auth_method_announcement");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, auth_method_announcement_test_core_request_marshall_incomplete);
    tcase_add_test(tc, auth_method_announcement_test_core_request_marshall_complete);
    tcase_add_test(tc, auth_method_announcement_test_core_on_write_success_no_authentication);
    tcase_add_test(tc, auth_method_announcement_test_core_on_write_success_authentication);
    tcase_add_test(tc, auth_method_announcement_test_core_on_write_current);
    

    suite_add_tcase(s, tc);

    return s;
}