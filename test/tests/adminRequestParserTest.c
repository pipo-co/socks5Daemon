#include "parsers/adminRequestParser/adminRequestParser.c"

#include <check.h>
#include <stdint.h>
#include <stdio.h>

uint8_t query_with_no_args[] = {
    QUERY, TOTAL_HISTORIC_CONNECTIONS,
};

uint8_t query_with_string[] = {
    QUERY, USER_TOTAL_CONCURRENT_CONNECTIONS, 0x05,
    'N', '4', 'C', 'H', '0','\0',
};

uint8_t modification_with_user[] = {
    MODIFICATION, ADD_USER, 
    0x05, 'N', '4', 'C', 'H', '0',
    0x06, 'S', '4', 'G', 'U', 'E', 'S',
    0x05
};

#define MODIFIER_WITH_UINT8_TP 0x06
#define INVALID_TYPE 0x06
#define INVALID_QUERY 0x32
#define INVALID_MODIFIER 0x32

uint8_t modifier_with_uint8[] = {
    MODIFICATION, TOGGLE_PASSWORD_SPOOFING, MODIFIER_WITH_UINT8_TP,
};

uint8_t modifier_with_uint32[] = {
    MODIFICATION, SET_BUFFER_SIZE,
    0x01, 0x00, 0xff, 0x02,
};

uint8_t invalid_type[] = {
    INVALID_TYPE, 0x01,
};

uint8_t invalid_query[] = {
    QUERY, INVALID_QUERY,
};

uint8_t invalid_modifier[] = {
    MODIFICATION, INVALID_MODIFIER,
};

START_TEST (admin_request_parser_query_with_no_args) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(query_with_no_args), query_with_no_args);
    buffer_write_adv(&b, sizeof(query_with_no_args));
    
    admin_request_parser_consume(&p, &b, &errored);

    

    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(!errored);
    ck_assert_uint_eq(QUERY, p.type);
    ck_assert_uint_eq(TOTAL_HISTORIC_CONNECTIONS, p.command);
}
END_TEST

START_TEST (admin_request_parser_query_with_string) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(query_with_string), query_with_string);
    buffer_write_adv(&b, sizeof(query_with_string));
    
    admin_request_parser_consume(&p, &b, &errored);
    
    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(!errored);
    ck_assert(buffer_can_read(&b));
    ck_assert_uint_eq(QUERY, p.type);
    ck_assert_uint_eq(USER_TOTAL_CONCURRENT_CONNECTIONS, p.command);
    ck_assert_str_eq((char *) query_with_string + 3, (char *) p.args.string);
}
END_TEST

START_TEST (admin_request_parser_modifier_with_uint8) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(modifier_with_uint8), modifier_with_uint8);
    buffer_write_adv(&b, sizeof(modifier_with_uint8));
    
    admin_request_parser_consume(&p, &b, &errored);
    
    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(!errored);
    ck_assert_uint_eq(MODIFICATION, p.type);
    ck_assert_uint_eq(TOGGLE_PASSWORD_SPOOFING, p.command);
    ck_assert_uint_eq(MODIFIER_WITH_UINT8_TP, p.args.uint8);
}
END_TEST

START_TEST (admin_request_parser_modifier_with_uint32) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(modifier_with_uint32), modifier_with_uint32);
    buffer_write_adv(&b, sizeof(modifier_with_uint32));
    
    admin_request_parser_consume(&p, &b, &errored);
    
    
    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(!errored);
    ck_assert_uint_eq(MODIFICATION, p.type);
    ck_assert_uint_eq(SET_BUFFER_SIZE, p.command);
    ck_assert_uint_eq((0x01 << 24) + (0xff << 8) + 0x02, p.args.uint32);
}
END_TEST

START_TEST (admin_request_parser_modifier_with_user) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(modification_with_user), modification_with_user);
    buffer_write_adv(&b, sizeof(modification_with_user));
    
    admin_request_parser_consume(&p, &b, &errored);
    

    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(!errored);
    ck_assert_uint_eq(MODIFICATION, p.type);
    ck_assert_uint_eq(ADD_USER, p.command);
    ck_assert_str_eq("N4CH0", (char *) p.args.user.uname);
    ck_assert_str_eq("S4GUES",  (char *) p.args.user.pass);
    ck_assert_uint_eq(0x05, p.args.user.admin);
}
END_TEST

START_TEST (admin_request_parser_invalid_type) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(invalid_type), invalid_type);
    buffer_write_adv(&b, sizeof(invalid_type));
    
    admin_request_parser_consume(&p, &b, &errored);
    
    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(errored);
    ck_assert(buffer_can_read(&b));
}
END_TEST

START_TEST (admin_request_parser_invalid_query) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(invalid_query), invalid_query);
    buffer_write_adv(&b, sizeof(invalid_query));
    
    admin_request_parser_consume(&p, &b, &errored);
    

    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(errored);
}
END_TEST

START_TEST (admin_request_parser_invalid_modification) {

    AdminRequestParser p;

    admin_request_parser_init(&p);

    Buffer b;
    bool errored;

    buffer_init(&b, sizeof(invalid_modifier), invalid_query);
    buffer_write_adv(&b, sizeof(invalid_query));
    
    admin_request_parser_consume(&p, &b, &errored);
    
    

    ck_assert(admin_request_parser_is_done(&p, &errored));
    ck_assert(errored);
}
END_TEST

Suite * admin_request_parser_test_suite(void) {

    Suite *s   = suite_create("admin_request_parser");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, admin_request_parser_query_with_no_args);
    tcase_add_test(tc, admin_request_parser_query_with_string);
    tcase_add_test(tc, admin_request_parser_modifier_with_uint8);
    tcase_add_test(tc, admin_request_parser_modifier_with_uint32);
    tcase_add_test(tc, admin_request_parser_modifier_with_user);
    tcase_add_test(tc, admin_request_parser_invalid_type);
    tcase_add_test(tc, admin_request_parser_invalid_query);
    tcase_add_test(tc, admin_request_parser_invalid_modification);

    suite_add_tcase(s, tc);

    return s;
}