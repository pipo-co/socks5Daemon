#include "states/requestSuccessful/requestSuccessful.c"

START_TEST (request_successful_test_core_request_marshall_incomplete) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(4*sizeof(*dummyBuffer));
    buffer_init(&buff, 4, dummyBuffer);
    size_t bytes = 0;

    request_marshall(&buff, &bytes);

    ck_assert_uint_eq(bytes, 4);
    ck_assert_uint_eq(buffer_read(&buff), SOCKS_VERSION);
    ck_assert_uint_eq(buffer_read(&buff), RESPONSE_SUCCESS_MESSAGE);
    ck_assert_uint_eq(buffer_read(&buff), RSV);
    ck_assert_uint_eq(buffer_read(&buff), ATYP);

    free(dummyBuffer);
}
END_TEST

START_TEST (request_successful_test_core_request_marshall_complete) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(11*sizeof(*dummyBuffer));
    buffer_init(&buff, 11, dummyBuffer);
    size_t bytes = 0;

    request_marshall(&buff, &bytes);

    ck_assert_uint_eq(bytes, 10);
    ck_assert_uint_eq(buffer_read(&buff), SOCKS_VERSION);
    ck_assert_uint_eq(buffer_read(&buff), RESPONSE_SUCCESS_MESSAGE);
    ck_assert_uint_eq(buffer_read(&buff), RSV);
    ck_assert_uint_eq(buffer_read(&buff), ATYP);
    ck_assert_uint_eq(buffer_read(&buff), 0x00);
    ck_assert_uint_eq(buffer_read(&buff), 0x00);
    ck_assert_uint_eq(buffer_read(&buff), 0x00);
    ck_assert_uint_eq(buffer_read(&buff), 0x00);
    ck_assert_uint_eq(buffer_read(&buff), 0x00);
    ck_assert_uint_eq(buffer_read(&buff), 0x00);
    
    
    free(dummyBuffer);
    
}
END_TEST



START_TEST (request_successful_test_core_on_write_success) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP session = malloc(sizeof(*session));

    SelectorStateMachine stm;
    stm.current = REQUEST_SUCCESSFUL;
    session->sessionStateMachine = stm;

    RequestHeader requestHeader;
    requestHeader.bytes = REPLY_SIZE;
    
    session->socksHeader.requestHeader = requestHeader;

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

    ClientInfo clientInfo;
    Connection serverConnection;
    UserInfo * user = malloc(sizeof(*user));

    char buffer[10];
    user->username = buffer;
    user->connectionCount = 0;
    memcpy(user->username, "tobi", sizeof("tobi"));
    
    clientInfo.user = user;

    session->clientInfo = clientInfo;
    session->serverConnection = serverConnection;
    
    key->s = selector;
    key->data = session;

    unsigned state = request_successful_on_write(key);

    ck_assert_uint_eq(state, FORWARDING);

    selector_destroy(selector);
    
    free(user);
    free(key);
    free(session);

    
}
END_TEST

START_TEST (request_successful_test_core_on_write_current) {

    SelectorEvent *key =  malloc(sizeof(*key));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = REQUEST_SUCCESSFUL;
    socks5_p->sessionStateMachine = stm;

    RequestHeader requestHeader;
    requestHeader.bytes = 0;
    
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

    unsigned state = request_successful_on_write(key);

    ck_assert_uint_eq(state, REQUEST_SUCCESSFUL);
    
    selector_destroy(selector);
    free(key);
    free(socks5_p);

    
}
END_TEST


Suite * request_success_test_suite(void) {

    Suite *s   = suite_create("request_successful");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, request_successful_test_core_request_marshall_incomplete);
    tcase_add_test(tc, request_successful_test_core_request_marshall_complete);
    tcase_add_test(tc, request_successful_test_core_on_write_success);
    tcase_add_test(tc, request_successful_test_core_on_write_current);
    

    suite_add_tcase(s, tc);

    return s;
}