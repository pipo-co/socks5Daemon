#include "utilities/base64/base64.c"

#define N(x) (sizeof(x)/sizeof((x)[0]))

START_TEST (base64_encode_test) {

    char input1[] = "holacomovasoytobiasbrandy";

    char output1[BASE64_ENCODE_SIZE(N(input1) - 1)];

    base64_encode((uint8_t*)input1, N(input1) - 1, output1, false);

    ck_assert_str_eq("aG9sYWNvbW92YXNveXRvYmlhc2JyYW5keQ", output1);

    char input2[] = "una banana";

    char output2[BASE64_ENCODE_SIZE(N(input2) - 1)];

    base64_encode((uint8_t*)input2, N(input2) - 1, output2, true);

    ck_assert_str_eq("dW5hIGJhbmFuYQ==", output2);
}
END_TEST

START_TEST (base64_decode_test) {

    char input1[] = "aG9sYWNvbW92YXNveXRvYmlhc2JyYW5keQ==";

    char output1[BASE64_DECODE_SIZE(N(input1) - 1)];

    size_t outLen = base64_decode(input1, (uint8_t*)output1);

    output1[outLen] = 0;

    ck_assert_str_eq("holacomovasoytobiasbrandy", output1);

    char input2[] = "dW5hIGJhbmFuYQ==";

    char output2[BASE64_DECODE_SIZE(N(input2) - 1)];

    outLen = base64_decode(input2, (uint8_t*)output2);

    output2[outLen] = 0;

    ck_assert_str_eq("una banana", output2);

}
END_TEST

Suite * base64_test_suite(void) {

    Suite *s   = suite_create("base64");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, base64_encode_test);
    tcase_add_test(tc, base64_decode_test);

    suite_add_tcase(s, tc);

    return s;
}