#ifndef AUTH_METHOD_ANNOUNCEMENT_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define AUTH_METHOD_ANNOUNCEMENT_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5.h"

#define SOCKS_VERSION 0x05
#define INITIAL_RESPONSE_SIZE 2

enum AuthMethods {
    NO_ACCEPTABLE_METHODS = 0xff, 
    NO_AUTHENTICATION = 0x00, 
    USER_PASSWORD = 0x02
    };

unsigned method_announcement_on_pre_write(struct selector_key *key);

unsigned method_announcement_on_post_write(struct selector_key *key);

void method_announcement_on_departure(const unsigned state, struct selector_key *key);

#endif