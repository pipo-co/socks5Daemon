#ifndef AUTH_REQUEST_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define AUTH_REQUEST_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5.h"
#include "authRequestParser.h"

typedef struct AuthRequestHeader{
    AuthRequestParser parser;
    size_t bytes;
}AuthRequestHeader;

void auth_request_on_arrival (const unsigned state, struct selector_key *key);

unsigned auth_request_on_post_read(struct selector_key *key);

#endif