#include "parsers/adminRequestParser/adminResponseBuilder.c"

#include <check.h>

START_TEST (admin_response_builder_core_uint8) {
    Buffer buff;
    uint8_t *dummyBuffer = malloc(sizeof(*dummyBuffer));
    buffer_init(&buff, 1, dummyBuffer);

    AdminResponseBuilderContainer adminResponseBuilder;
    adminResponseBuilder.admin_response_builder = admin_response_builder_uint8;
    adminResponseBuilder.cmd = 0x00;
    adminResponseBuilder.type = 0x07;
    CommandResponseBuilderData data;
    data.uint8 = 16;
    adminResponseBuilder.data = data;

    adminResponseBuilder.admin_response_builder(&adminResponseBuilder, &buff);

    ck_assert_uint_eq(0x00, buffer_read(&buff));
    ck_assert_uint_eq(0x07, buffer_read(&buff));
    ck_assert_uint_eq(16, buffer_read(&buff));

}END_TEST


Suite * admin_response_builder_test_suite(void) {

    Suite *s   = suite_create("auth_error");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, admin_response_builder_core_uint8);


    suite_add_tcase(s, tc);

    return s;
}



