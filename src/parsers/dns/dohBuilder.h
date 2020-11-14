#ifndef DNS_RESPONSE_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define DNS_RESPONSE_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "argsHandler/argsHandler.h"
#include "buffer/buffer.h"

bool doh_builder_build(Buffer * buff, char * domain, uint16_t qtype, Socks5Args * args, size_t bufSize);

#endif
