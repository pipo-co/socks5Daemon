#ifndef IP_CONNECT_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define IP_CONNECT_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5.h"

enum RepplyValues {GENERAL_SOCKS_SERVER_FAILURE = 0x01, NETWORK_UNREACHABLE = 0x03, HOST_UNREACHABLE = 0x04, CONNECTION_REFUSED = 0x05};

unsigned ip_connect_on_post_write(struct selector_key *key);


#endif