#include "states/forwarding/forwarding.c"

uint8_t forwardingDummyBuffer[] = {
    0x05, 0x01, 0x02
};

START_TEST (forwarding_test_core_on_read_flush_closer) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    socks5_p->clientConnection.state = CLOSING;

    event->data = socks5_p;

    unsigned state = forwarding_on_read(event);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

    free(socks5_p);
    free(event);
   
    SelectorEvent *event2 =  malloc(sizeof(*event2));

    SessionHandlerP socks5_p2 = malloc(sizeof(*socks5_p2));

    socks5_p2->serverConnection.state = CLOSING;

    event2->data = socks5_p2;

    state = forwarding_on_read(event2);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

    free(socks5_p2);
    free(event2);
}
END_TEST

START_TEST (forwarding_test_core_on_read_server) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FORWARDING;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->output, N(forwardingDummyBuffer), forwardingDummyBuffer);
    buffer_write_adv(&socks5_p->output, N(forwardingDummyBuffer));

    socks5_p->clientConnection.state = OPEN;
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

    unsigned state = forwarding_on_read(event);

    ck_assert_uint_eq(state, FORWARDING);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (forwarding_test_core_on_read_client) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FORWARDING;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(forwardingDummyBuffer), forwardingDummyBuffer);
    buffer_write_adv(&socks5_p->input, N(forwardingDummyBuffer));

    socks5_p->clientConnection.state = OPEN;
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

    event->fd = socks5_p->clientConnection.fd;
    event->s = selector;
    event->data = socks5_p;

    unsigned state = forwarding_on_read(event);

    ck_assert_uint_eq(state, FORWARDING);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (forwarding_test_core_on_write_server) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FORWARDING;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->input, N(forwardingDummyBuffer), forwardingDummyBuffer);
    buffer_write_adv(&socks5_p->input, N(forwardingDummyBuffer));

    socks5_p->clientConnection.state = OPEN;
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

    unsigned state = forwarding_on_read(event);

    ck_assert_uint_eq(state, FORWARDING);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

START_TEST (forwarding_test_core_on_write_client) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    SelectorStateMachine stm;
    stm.current = FORWARDING;
    socks5_p->sessionStateMachine = stm;


    buffer_init(&socks5_p->output, N(forwardingDummyBuffer), forwardingDummyBuffer);
    buffer_write_adv(&socks5_p->output, N(forwardingDummyBuffer));

    socks5_p->clientConnection.state = OPEN;
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

    event->fd = socks5_p->clientConnection.fd;
    event->s = selector;
    event->data = socks5_p;

    unsigned state = forwarding_on_read(event);

    ck_assert_uint_eq(state, FORWARDING);

    selector_destroy(selector);
    free(socks5_p);
    free(event);

}
END_TEST

Suite * forwarding_test_suite(void) {

    Suite *s   = suite_create("forwarding");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, forwarding_test_core_on_read_flush_closer);
    tcase_add_test(tc, forwarding_test_core_on_read_server);
    tcase_add_test(tc, forwarding_test_core_on_read_client);
    tcase_add_test(tc, forwarding_test_core_on_write_server);
    tcase_add_test(tc, forwarding_test_core_on_write_client);
    

    suite_add_tcase(s, tc);

    return s;
}