#include <stdlib.h>
#include <check.h>
#include "states/request/request.c"

#define N(x) (sizeof(x)/sizeof((x)[0]))

uint8_t request_test_input_unsupported_address_type[] = {
    0x05, 0x01, 0x00, 0xFE,
    /* 172.217.173.14 */ 0xac, 0xd9, 0xad, 0x0e,
    /* Port: 592 */ 0x02, 0x50,
};


START_TEST (request_test_parsing_error) {

    struct selector_key * key = malloc(sizeof(*key));
    Socks5Handler * socks_p = malloc(sizeof(*socks_p));
    Buffer buff;

    buffer_init(&buff, N(request_parser_test_input_unsupported_address_type), request_parser_test_input_unsupported_address_type);
    buffer_write_adv(&buff, N(request_parser_test_input_unsupported_address_type));

    key->data = socks_p;
    socks_p->input = buff;

    unsigned state = request_on_post_read(key);

    ck_assert_uint_eq(REQUEST_ERROR, state);

    free(key);
    free(socks_p);
}
END_TEST


Suite * request_test_suite(void) {

    Suite *s   = suite_create("request");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, request_test_parsing_error);
    suite_add_tcase(s, tc);

    return s;
}