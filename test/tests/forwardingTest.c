#include "states/forwarding/forwarding.c"

START_TEST (forwarding_test_core_on_post_write_current_flush_closer) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

    socks5_p->clientConnection.state = CLOSING;

    unsigned state = forwarding_on_post_read(event);

    ck_assert_uint_eq(state, FLUSH_CLOSER);

   
}
END_TEST

START_TEST (forwarding_test_core_on_post_write_current_flush_closer) {

    SelectorEvent *event =  malloc(sizeof(*event));

    SessionHandlerP socks5_p = malloc(sizeof(*socks5_p));

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

    Connection serverConnection;
    serverConnection.state = OPEN;
    serverConnection.fd = 2;

    socks5_p->serverConnection = serverConnection;
    event->fd = 2;

   
}
END_TEST

Suite * forwarding_test_suite(void) {

    Suite *s   = suite_create("forwarding");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, forwarding_test_core_on_post_write_current_flush_closer);

    suite_add_tcase(s, tc);

    return s;
}