#ifndef AUTH_ERROR_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define AUTH_ERROR_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5.h"

#define SOCKS_VERSION 0x05
#define UNSUCCESSFUL 0xFF
#define AUTH_ERROR_RESPONSE_SIZE 2

unsigned auth_error_on_pre_write(struct selector_key *key);

unsigned auth_error_on_post_write(struct selector_key *key);

void auth_error_on_departure(const unsigned state, struct selector_key *key);

#endif