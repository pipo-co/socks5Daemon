#include "states/close/flushClosy/flushClosy.c"

uint8_t flushClosyDummyBufferInput[] = {
    0x05, 0x01, 0x02
};

uint8_t flushClosyDummyBufferOutput[] = {
    0x05, 0x01, 0x02
};


START_TEST (flush_closy_test_core_on_post_write_server) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSY;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(flushClosyDummyBufferInput), flushClosyDummyBufferInput);
    buffer_write_adv(&socks5_p->input, N(flushClosyDummyBufferInput));

    buffer_init(&socks5_p->output, N(flushClosyDummyBufferOutput), flushClosyDummyBufferOutput);

    socks5_p->clientConnection.state = OPEN;
    socks5_p->clientConnection.fd = 2;
    socks5_p->serverConnection.state = CLOSING;
    socks5_p->serverConnection.fd = 3;


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

    event->s = selector;
    event->data = socks5_p;

    unsigned state = flush_closy_on_post_write(event);

    ck_assert_uint_eq(state, FLUSH_CLOSY);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (flush_closy_test_core_on_post_write_client) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSY;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(flushClosyDummyBufferInput), flushClosyDummyBufferInput);

    buffer_init(&socks5_p->output, N(flushClosyDummyBufferInput), flushClosyDummyBufferInput);
    buffer_write_adv(&socks5_p->output, N(flushClosyDummyBufferInput));


    socks5_p->clientConnection.state = CLOSING;
    socks5_p->clientConnection.fd = 2;
    socks5_p->serverConnection.state = OPEN;
    socks5_p->serverConnection.fd = 3;


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

    event->s = selector;
    event->data = socks5_p;

    unsigned state = flush_closy_on_post_write(event);

    ck_assert_uint_eq(state, FLUSH_CLOSY);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (flush_closy_test_core_on_post_write_success) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSY;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(flushClosyDummyBufferInput), flushClosyDummyBufferInput);

    buffer_init(&socks5_p->output, N(flushClosyDummyBufferInput), flushClosyDummyBufferInput);


    socks5_p->clientConnection.state = CLOSING;
    socks5_p->clientConnection.fd = 2;
    socks5_p->serverConnection.state = CLOSING;
    socks5_p->serverConnection.fd = 3;


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

    event->s = selector;
    event->data = socks5_p;

    unsigned state = flush_closy_on_post_write(event);

    ck_assert_uint_eq(state, FINISH);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

Suite * flush_closy_test_suite(void) {

    Suite *s   = suite_create("flushClosy");
    TCase *tc  = tcase_create("core");

    
    tcase_add_test(tc, flush_closy_test_core_on_post_write_server);
    tcase_add_test(tc, flush_closy_test_core_on_post_write_client);
    tcase_add_test(tc, flush_closy_test_core_on_post_write_success);
    

    suite_add_tcase(s, tc);

    return s;
}