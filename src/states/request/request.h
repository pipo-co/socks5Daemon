#ifndef REQUEST_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define REQUEST_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

#include "../buffer/buffer.h"
#include "../netutils/netutils.h"
#include "requestParser.h"
#include "socks5.h"

enum RepplyValues {SUCCESFUL = 0x00, GENERAL_SOCKS_SERVER_FAILURE = 0x01, NETWORK_UNREACHABLE = 0x03, HOST_UNREACHABLE = 0x04, CONNECTION_REFUSED = 0x05};

typedef struct RequestHeader{
    RequestParser parser;
    uint8_t bytes;
    uint8_t rep;

}RequestHeader;

void request_on_arrival (const unsigned state, struct selector_key *key);

unsigned request_on_post_read(struct selector_key *key);

#endif