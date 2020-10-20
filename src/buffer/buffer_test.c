#include <stdlib.h>
#include <check.h>

// asi se puede probar las funciones internas
#include "buffer.c"

#define N(x) (sizeof(x)/sizeof((x)[0]))


START_TEST (test_buffer_misc) {
    struct buffer buf;
    buffer *b = &buf;
    uint8_t direct_buff[6];
    buffer_init(&buf, N(direct_buff), direct_buff);
    ck_assert_ptr_eq(&buf, b);

    ck_assert_int_eq(true,  buffer_can_write(b));
    ck_assert_int_eq(false, buffer_can_read(b));

    size_t wbytes = 0, rbytes = 0;
    uint8_t *ptr = buffer_write_ptr(b, &wbytes);
    ck_assert_uint_eq(6, wbytes);
    // escribo 4 bytes
    uint8_t first_write [] = {
        'H', 'O', 'L', 'A',
    };
    memcpy(ptr, first_write, sizeof(first_write));
    buffer_write_adv(b, sizeof(first_write));

    // quedan 2 libres para escribir
    buffer_write_ptr(b, &wbytes);
    ck_assert_uint_eq(2, wbytes);

    // tengo por leer
    buffer_read_ptr(b, &rbytes);
    ck_assert_uint_eq(4, rbytes);

    // leo 3 del buffer
    ck_assert_uint_eq('H', buffer_read(b));
    ck_assert_uint_eq('O', buffer_read(b));
    ck_assert_uint_eq('L', buffer_read(b));

    // queda 1 por leer
    buffer_read_ptr(b, &rbytes);
    ck_assert_uint_eq(1, rbytes);

    // quiero escribir..tendria que seguir habiendo 2 libres
    ptr = buffer_write_ptr(b, &wbytes);
    ck_assert_uint_eq(2, wbytes);

    uint8_t second_write [] = {
        ' ', 'M',
    };
    memcpy(ptr, second_write, sizeof(second_write));
    buffer_write_adv(b, sizeof(second_write));

    ck_assert_int_eq(false, buffer_can_write(b));
    buffer_write_ptr(b, &wbytes);
    ck_assert_uint_eq(0, wbytes);

    // tiene que haber 2 + 1 para leer
    ptr = buffer_read_ptr(b, &rbytes);
    ck_assert_uint_eq(3, rbytes);
    ck_assert_ptr_ne(ptr, b->data);

    buffer_compact(b);
    ck_assert_ptr_eq(b->data, buffer_read_ptr(b, &rbytes));
    ck_assert_uint_eq(3, rbytes);
    ck_assert_ptr_eq(b->data + 3, buffer_write_ptr(b, &wbytes));
    ck_assert_uint_eq(3, wbytes);

    uint8_t third_write [] = {
        'U', 'N', 'D',
    };
    memcpy(ptr, third_write, sizeof(third_write));
    buffer_write_adv(b, sizeof(third_write));

    buffer_write_ptr(b, &wbytes);
    ck_assert_uint_eq(0, wbytes);
    ck_assert_ptr_eq(b->data, buffer_read_ptr(b, &rbytes));
    buffer_read_adv(b, rbytes);
    buffer_read_ptr(b, &rbytes);
    ck_assert_uint_eq(0, rbytes);
    ck_assert_ptr_eq(b->data, buffer_write_ptr(b, &wbytes));
    ck_assert_uint_eq(6, wbytes);

    buffer_compact(b);
    buffer_read_ptr(b, &rbytes);
    ck_assert_uint_eq(0, rbytes);
    buffer_write_ptr(b, &wbytes);
    ck_assert_uint_eq(N(direct_buff), wbytes);

}
END_TEST

Suite *
suite(void) {
    Suite *s   = suite_create("buffer");
    TCase *tc  = tcase_create("buffer");

    tcase_add_test(tc, test_buffer_misc);
    suite_add_tcase(s, tc);

    return s;
}

int
main(void) {
    SRunner *sr  = srunner_create(suite());
    int number_failed;

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
