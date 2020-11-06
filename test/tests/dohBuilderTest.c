#include "parsers/dns/dohBuilder.c"

char * domain1 = "www.example.com";
char * domain_max_size = "gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgla.agligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgl.gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgla.gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgl";
char * domain_too_long = "gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiaf.gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiaf.gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiaf.gligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiafgligvpgrlurqhvmayiaf";
uint8_t doh_query_succes_domain1[] = { /* Packet 172 */
    0x47, 0x45, 0x54, 0x20, 0x2f, 0x64, 0x6e, 0x73, 
    0x2d, 0x71, 0x75, 0x65, 0x72, 0x79, 0x3f, 0x64, 
    0x6e, 0x73, 0x3d, 0x41, 0x41, 0x41, 0x42, 0x41, 
    0x41, 0x41, 0x42, 0x41, 0x41, 0x41, 0x41, 0x41, 
    0x41, 0x41, 0x41, 0x41, 0x33, 0x64, 0x33, 0x64, 
    0x77, 0x64, 0x6c, 0x65, 0x47, 0x46, 0x74, 0x63, 
    0x47, 0x78, 0x6c, 0x41, 0x32, 0x4e, 0x76, 0x62, 
    0x51, 0x41, 0x41, 0x41, 0x51, 0x41, 0x42, 0x20, 
    0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 
    '\r', '\n' 
};

uint8_t dns_query_succes_domain1[] = {
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 
    0x01, 
};


START_TEST (doh_builder_test_succes_first_line) {
    
    Buffer buf;
    Socks5Args args;
    parse_args(0, NULL, &args);
    args.doh.path = "/dns-query";
    uint8_t *ans = doh_query_succes_domain1;
    doh_builder_build(&buf, domain1, AF_INET, &args);
    uint8_t b;

    while (buffer_can_read(&buf) && b != '\n'){
        b =  buffer_read(&buf);
        ck_assert_uint_eq(*(ans++), b);
    }

    free(buf.data);
}
END_TEST

START_TEST (doh_builder_test_dns_query) {
    
    uint8_t buffer[MAX_DNS_QUERY_SIZE];
    size_t size = doh_builder_build_dns_query(domain1, A, buffer, MAX_DNS_QUERY_SIZE);

    for (size_t i = 0; i < size; i++) {
        ck_assert_uint_eq(dns_query_succes_domain1[i], buffer[i]);
    }
       
}
END_TEST

START_TEST (doh_builder_test_url_too_long) {
    
    uint8_t buffer[MAX_DNS_QUERY_SIZE];
    size_t size = doh_builder_build_dns_query(domain_too_long, A, buffer, MAX_DNS_QUERY_SIZE);

    ck_assert_uint_eq(0, size);
}
END_TEST

START_TEST (doh_builder_test_invalid_q_type) {
    
    Buffer buf;
    Socks5Args args;
    parse_args(0, NULL, &args);
    int ans = doh_builder_build(&buf, domain1, 0, &args);

    ck_assert_int_eq(-1, ans);
}
END_TEST

START_TEST (doh_builder_test_domain_name_max_size) {
    
    Buffer buf;
    Socks5Args args;
    parse_args(0, NULL, &args);
    int ans = doh_builder_build(&buf, domain_max_size, AF_INET, &args);

    ck_assert_int_eq(0, ans);
    free(buf.data);
}
END_TEST

Suite * doh_builder_test_suite(void) {

    Suite *s   = suite_create("dohBuilder");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, doh_builder_test_succes_first_line);
    tcase_add_test(tc, doh_builder_test_dns_query);
    tcase_add_test(tc, doh_builder_test_url_too_long);
    tcase_add_test(tc, doh_builder_test_invalid_q_type);
    tcase_add_test(tc, doh_builder_test_domain_name_max_size);


    suite_add_tcase(s, tc);
    return s;
}