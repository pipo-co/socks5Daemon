#ifndef HELLO_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define HELLO_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

#include "buffer/buffer.h"
#include "helloParser.h"
#include "socks5/socks5.h"

enum AuthMethods {
    NO_ACCEPTABLE_METHODS = 0xff, 
    NO_AUTHENTICATION = 0x00, 
    USER_PASSWORD = 0x02
    };

typedef struct HelloHeader{

    HelloParser parser;
    size_t bytes;
    
}HelloHeader;

void hello_on_arrival (const unsigned state, struct selector_key *key);

unsigned hello_on_read_ready(struct selector_key *key);

#endif