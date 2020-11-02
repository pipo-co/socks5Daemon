#ifndef REQUEST_SUCCESSFUL_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define REQUEST_SUCCESSFUL_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5.h"

#define REPLY_SIZE 10
#define SOCKS_VERSION 0x05
#define SUCCESS 0x00
#define RSV 0x00
#define ATYP 0x01


unsigned request_successful_on_pre_write(struct selector_key *key);

unsigned request_successful_on_post_write(struct selector_key *key);

void request_successful_on_departure(const unsigned state, struct selector_key *key);

#endif