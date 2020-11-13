#include "parsers/authRequest/authRequestParser.c"


uint8_t authRequestTestSuccess[] = { 
    0x01, 0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x08, 
    0x70, 0x61, 0x70, 0x61, 0x6e, 0x61, 0x74, 0x61 
};

uint8_t authRequestTestInvalidUlen[] = { 
    0x01, 0x00
};

uint8_t authRequestTestInvalidVersion[] = {
    0x00
};

uint8_t authRequestTestInvalidPlen[] = { 
    0x01, 0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00
};

START_TEST (auth_request_parser_test_core_success_feed) {

    AuthRequestParser parser;
    AuthRequestParser *p = &parser;
    bool errored;
    uint8_t i = 0;
     
    auth_request_parser_init(p);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_VERSION);

    auth_request_parser_feed(p, authRequestTestSuccess[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_ULEN);

    auth_request_parser_feed(p, authRequestTestSuccess[i++]);
    
    ck_assert(p->currentState == AUTH_REQUEST_PARSER_UNAME);

    ck_assert_uint_eq(p->ulen, 5);

    while(i < 6){
        auth_request_parser_feed(p, authRequestTestSuccess[i++]);
        ck_assert(p->currentState == AUTH_REQUEST_PARSER_UNAME);
    }

    auth_request_parser_feed(p, authRequestTestSuccess[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_PLEN);

    auth_request_parser_feed(p, authRequestTestSuccess[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_PASSWORD);

    ck_assert_uint_eq(p->plen, 8);

    while(i < 15){
        auth_request_parser_feed(p, authRequestTestSuccess[i++]);
        ck_assert(p->currentState == AUTH_REQUEST_PARSER_PASSWORD);
    }

    auth_request_parser_feed(p, authRequestTestSuccess[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_SUCCESS);

    ck_assert(auth_request_parser_is_done(p->currentState, &errored));

    ck_assert(errored == false);
}
END_TEST

START_TEST (auth_request_parser_test_core_success_consume) {

    uint8_t *input = authRequestTestSuccess;
    uint8_t inputLen = N(authRequestTestSuccess);

    Buffer buffer;
    Buffer *b = &buffer;

    buffer_init(b, inputLen, input);
    buffer_write_adv(b, inputLen);

    AuthRequestParser parser;
    AuthRequestParser *p = &parser;
    bool errored;

    auth_request_parser_init(p);

    ck_assert_uint_eq(p->currentState, AUTH_REQUEST_PARSER_VERSION);

    ck_assert(auth_request_parser_consume(b, p, &errored));

    ck_assert_uint_eq(p->ulen, 5);

    ck_assert_uint_eq(p->plen, 8);

    ck_assert(!errored);
}
END_TEST

START_TEST (auth_request_parser_test_core_invalid_version_feed) {

    AuthRequestParser parser;
    AuthRequestParser *p = &parser;
    bool errored;
    uint8_t i = 0;
     
    auth_request_parser_init(p);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_VERSION);

    auth_request_parser_feed(p, authRequestTestInvalidVersion[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_INVALID_STATE);
    
    ck_assert(auth_request_parser_is_done(p->currentState, &errored));

    ck_assert(errored == true);
}
END_TEST

START_TEST (auth_request_parser_test_core_invalid_ulen_feed) {

    AuthRequestParser parser;
    AuthRequestParser *p = &parser;
    bool errored;
    uint8_t i = 0;
     
    auth_request_parser_init(p);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_VERSION);

    auth_request_parser_feed(p, authRequestTestInvalidUlen[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_ULEN);

    auth_request_parser_feed(p, authRequestTestInvalidUlen[i++]);
    
    ck_assert(p->currentState == AUTH_REQUEST_PARSER_INVALID_STATE);

    ck_assert(auth_request_parser_is_done(p->currentState, &errored));

    ck_assert(errored == true);
}
END_TEST

START_TEST (auth_request_parser_test_core_invalid_plen_feed) {

    AuthRequestParser parser;
    AuthRequestParser *p = &parser;
    bool errored;
    uint8_t i = 0;
     
    auth_request_parser_init(p);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_VERSION);

    auth_request_parser_feed(p, authRequestTestInvalidPlen[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_ULEN);

    auth_request_parser_feed(p, authRequestTestInvalidPlen[i++]);
    
    ck_assert(p->currentState == AUTH_REQUEST_PARSER_UNAME);

    ck_assert_uint_eq(p->ulen, 5);

    while(i < 6){
        auth_request_parser_feed(p, authRequestTestInvalidPlen[i++]);
        ck_assert(p->currentState == AUTH_REQUEST_PARSER_UNAME);
    }

    auth_request_parser_feed(p, authRequestTestInvalidPlen[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_PLEN);

    auth_request_parser_feed(p, authRequestTestInvalidPlen[i++]);

    ck_assert(p->currentState == AUTH_REQUEST_PARSER_INVALID_STATE);

    ck_assert(auth_request_parser_is_done(p->currentState, &errored));

    ck_assert(errored == true);
}
END_TEST


Suite * auth_request_parser_test_suite(void) {
    Suite *s   = suite_create("authRequestParser");

    TCase *tc  = tcase_create("core");
    tcase_add_test(tc, auth_request_parser_test_core_success_feed);
    tcase_add_test(tc, auth_request_parser_test_core_success_consume);
    tcase_add_test(tc, auth_request_parser_test_core_invalid_version_feed);
    tcase_add_test(tc, auth_request_parser_test_core_invalid_ulen_feed);
    tcase_add_test(tc, auth_request_parser_test_core_invalid_plen_feed);
    suite_add_tcase(s, tc);

    return s;
}
