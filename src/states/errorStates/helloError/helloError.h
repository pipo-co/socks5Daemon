#ifndef HELLO_ERROR_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define HELLO_ERROR_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5.h"

#define SOCKS_VERSION 0x05
#define NO_ACCEPTABLE_METHODS 0xFF
#define HELLO_ERROR_RESPONSE_SIZE 2

unsigned hello_error_on_pre_write(struct selector_key *key);

unsigned hello_error_on_post_write(struct selector_key *key);

void hello_error_on_departure(const unsigned state, struct selector_key *key);

#endif