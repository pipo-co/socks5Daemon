#include "states/close/flushCloser/flushCloser.c"

uint8_t flushCloserDummyBufferInput[] = {
    0x05, 0x01, 0x02
};

uint8_t flushCloserDummyBufferOutput[] = {
    0x05, 0x01, 0x02
};

START_TEST (flush_closer_test_core_on_read_flush_closing) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    socks5_p->clientConnection.fd = 2;
    socks5_p->clientConnection.state = CLOSING;

    event->fd = socks5_p->clientConnection.fd;
    event->data = socks5_p;

    unsigned state = flush_closer_on_read(event);

    ck_assert_uint_eq(state, FLUSH_CLOSY);

    free(socks5_p);
    free(event);
   
    SelectorEvent *event2 =  malloc(sizeof(*event2));

    SessionHandlerP socks5_p2 = malloc(sizeof(*socks5_p2));
    
    socks5_p2->clientConnection.fd = 2;
    socks5_p2->serverConnection.fd = 3;
    socks5_p2->serverConnection.state = CLOSING;

    event2->fd = socks5_p2->serverConnection.fd;
    event2->data = socks5_p2;

    state = flush_closer_on_read(event2);

    ck_assert_uint_eq(state, FLUSH_CLOSY);

    free(socks5_p2);
    free(event2);
}
END_TEST

START_TEST (flush_closer_test_core_on_read_server) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSER;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->output, N(flushCloserDummyBufferOutput), flushCloserDummyBufferOutput);
    buffer_write_adv(&socks5_p->output, N(flushCloserDummyBufferOutput));

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

    event->fd = socks5_p->serverConnection.fd;
    event->s = selector;
    event->data = socks5_p;

    unsigned state = flush_closer_on_read(event);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (flush_closer_test_core_on_read_client) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSER;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(flushCloserDummyBufferInput), flushCloserDummyBufferInput);
    buffer_write_adv(&socks5_p->input, N(flushCloserDummyBufferInput));

    socks5_p->clientConnection.state = OPEN;
    socks5_p->clientConnection.fd = 2;
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

    event->fd = socks5_p->clientConnection.fd;
    event->s = selector;
    event->data = socks5_p;

    unsigned state = flush_closer_on_read(event);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (flush_closer_test_core_on_write_server) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSER;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(flushCloserDummyBufferInput), flushCloserDummyBufferInput);
    buffer_write_adv(&socks5_p->input, N(flushCloserDummyBufferInput));

    buffer_init(&socks5_p->output, N(flushCloserDummyBufferOutput), flushCloserDummyBufferOutput);
    buffer_write_adv(&socks5_p->output, N(flushCloserDummyBufferOutput));

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

    unsigned state = flush_closer_on_write(event);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (flush_closer_test_core_on_write_client) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FLUSH_CLOSER;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(flushCloserDummyBufferInput), flushCloserDummyBufferInput);
    buffer_write_adv(&socks5_p->input, N(flushCloserDummyBufferInput));

    buffer_init(&socks5_p->output, N(flushCloserDummyBufferOutput), flushCloserDummyBufferOutput);
    buffer_write_adv(&socks5_p->output, N(flushCloserDummyBufferOutput));


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

    unsigned state = flush_closer_on_write(event);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

Suite * flush_closer_test_suite(void) {

    Suite *s   = suite_create("flushCloser");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, flush_closer_test_core_on_read_flush_closing);
    tcase_add_test(tc, flush_closer_test_core_on_read_server);
    tcase_add_test(tc, flush_closer_test_core_on_read_client);
    tcase_add_test(tc, flush_closer_test_core_on_write_server);
    tcase_add_test(tc, flush_closer_test_core_on_write_client);
    

    suite_add_tcase(s, tc);

    return s;
}