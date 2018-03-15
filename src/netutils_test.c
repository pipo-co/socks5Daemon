#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "netutils.h"

START_TEST (test_sockaddr_to_human_ipv4) {
    char buff[50] = {0};

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(9090),
    };
    addr.sin_addr.s_addr = htonl(0x01020304);
    const struct sockaddr *x = (const struct sockaddr *) &addr;

    ck_assert_str_eq(sockaddr_to_human(buff, sizeof(buff)/sizeof(buff[0]), x),
                     "1.2.3.4:9090");
    ck_assert_str_eq(sockaddr_to_human(buff, 5,  x), "unkn");
    ck_assert_str_eq(sockaddr_to_human(buff, 8,  x), "1.2.3.4");
    ck_assert_str_eq(sockaddr_to_human(buff, 9,  x), "1.2.3.4:");
    ck_assert_str_eq(sockaddr_to_human(buff, 10, x), "1.2.3.4:9");
    ck_assert_str_eq(sockaddr_to_human(buff, 11, x), "1.2.3.4:90");
    ck_assert_str_eq(sockaddr_to_human(buff, 12, x), "1.2.3.4:909");
    ck_assert_str_eq(sockaddr_to_human(buff, 13, x), "1.2.3.4:9090");
}
END_TEST


START_TEST (test_sockaddr_to_human_ipv6) {
    char buff[50] = {0};

    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(9090),
    };
    uint8_t *d = ((uint8_t *)&addr.sin6_addr);
    for(int i = 0; i < 16; i++) {
        d[i] = 0xFF;
    }

    const struct sockaddr *x = (const struct sockaddr *) &addr;
    ck_assert_str_eq(sockaddr_to_human(buff, 10, x), "unknown i");
    ck_assert_str_eq(sockaddr_to_human(buff, 39, x), "unknown ip:9090");
    ck_assert_str_eq(sockaddr_to_human(buff, 40, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    ck_assert_str_eq(sockaddr_to_human(buff, 41, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:");
    ck_assert_str_eq(sockaddr_to_human(buff, 42, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:9");
    ck_assert_str_eq(sockaddr_to_human(buff, 43, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:90");
    ck_assert_str_eq(sockaddr_to_human(buff, 44, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:909");
    ck_assert_str_eq(sockaddr_to_human(buff, 45, x),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:9090");
}
END_TEST

Suite * 
hello_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("socks");

    /* Core test case */
    tc = tcase_create("netutils");

    tcase_add_test(tc, test_sockaddr_to_human_ipv4);
    tcase_add_test(tc, test_sockaddr_to_human_ipv6);
    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hello_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

