#include <stdlib.h>
#include <check.h>

#define INITIAL_SIZE ((size_t) 1024)

// para poder testear las funciones estaticas
#include "selector/selector.c"

START_TEST (test_selector_error) {
    const SelectorStatus data[] = {
        SELECTOR_SUCCESS,
        SELECTOR_ENOMEM,
        SELECTOR_MAXFD,
        SELECTOR_IARGS,
        SELECTOR_IO,
    };
    // verifica que `selector_error' tiene mensajes especificos
    for(unsigned i = 0 ; i < N(data); i++) {
        ck_assert_str_ne(ERROR_DEFAULT_MSG, selector_error(data[i]));
    }
}
END_TEST

START_TEST (test_next_capacity) {
    const size_t data[] = {
         0,  1,
         1,  2,
         2,  4,
         3,  4,
         4,  8,
         7,  8,
         8, 16,
        15, 16,
        31, 32,
        16, 32,
        ITEMS_MAX_SIZE, ITEMS_MAX_SIZE,
        ITEMS_MAX_SIZE + 1, ITEMS_MAX_SIZE,
    };
    for(unsigned i = 0; i < N(data) / 2; i++ ) {
        ck_assert_uint_eq(data[i * 2 + 1] + 1, next_capacity(data[i*2]));
    }
}
END_TEST

START_TEST (test_ensure_capacity) {
    FdSelector s = selector_new(0);
    for(size_t i = 0; i < s->fd_size; i++) {
        ck_assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    size_t n = 1;
    ck_assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    ck_assert_uint_ge(s->fd_size, n);

    n = 10;
    ck_assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    ck_assert_uint_ge(s->fd_size, n);

    const size_t last_size = s->fd_size;
    n = ITEMS_MAX_SIZE + 1;
    ck_assert_int_eq(SELECTOR_MAXFD, ensure_capacity(s, n));
    ck_assert_uint_eq(last_size, s->fd_size);

    for(size_t i = 0; i < s->fd_size; i++) {
        ck_assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    selector_destroy(s);

    ck_assert_ptr_null(selector_new(ITEMS_MAX_SIZE + 1));
}
END_TEST

// callbacks de prueba
static void *data_mark = (void *)0x0FF1CE;
static unsigned destroy_count = 0;
static void
destroy_callback(struct SelectorEvent *key) {
    ck_assert_ptr_nonnull(key->s);
    ck_assert_int_ge(key->fd, 0);
    ck_assert_int_lt(key->fd, ITEMS_MAX_SIZE);

    ck_assert_ptr_eq(data_mark, key->data);
    destroy_count++;
}

START_TEST (test_selector_register_fd) {
    destroy_count = 0;
    FdSelector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);

    ck_assert_uint_eq(SELECTOR_IARGS,   selector_register(0, -1, 0, 0, data_mark));

    const struct FdHandler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    const struct Item *item = s->fds + fd;
    ck_assert_int_eq (fd,         s->max_fd);
    ck_assert_int_eq (fd,         item->fd);
    ck_assert_ptr_eq (&h,         item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    // destroy desregistró?
    ck_assert_uint_eq(1,          destroy_count);

}
END_TEST

START_TEST (test_selector_register_unregister_register) {
    destroy_count = 0;
    FdSelector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);

    const struct FdHandler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_unregister_fd(s, fd));

    const struct Item *item = s->fds + fd;
    ck_assert_int_eq (0,          s->max_fd);
    ck_assert_int_eq (FD_UNUSED,  item->fd);
    ck_assert_ptr_eq (0x00,       item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (0x00,       item->data);

    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    item = s->fds + fd;
    ck_assert_int_eq (fd,         s->max_fd);
    ck_assert_int_eq (fd,         item->fd);
    ck_assert_ptr_eq (&h,         item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    ck_assert_uint_eq(2,          destroy_count);

}
END_TEST

Suite * 
selector_test_suite(void) {
    Suite *s  = suite_create("nio");
    TCase *tc = tcase_create("nio");

    tcase_add_test(tc, test_next_capacity);
    tcase_add_test(tc, test_selector_error);
    tcase_add_test(tc, test_ensure_capacity);
    tcase_add_test(tc, test_selector_register_fd);
    tcase_add_test(tc, test_selector_register_unregister_register);
    suite_add_tcase(s, tc);

    return s;
}