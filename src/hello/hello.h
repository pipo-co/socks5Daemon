#ifndef HELLO_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define HELLO_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

#include "../buffer/buffer.h"

#define SOCKS_VERSION 0x05

// Default Methods
#define NO_AUTHENTICATION 0x00
#define NO_ACCEPTABLE_METHODS 0xFF

enum HelloState {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_ERROR_UNSUPPORTED_VERSION,
};

// Not an ADT to avoid unnecessary usages of malloc
typedef struct HelloParser {
    void (*on_auth_method)(struct HelloParser *parser, uint8_t method);

    void *data;

    enum HelloState current_state;

    uint8_t methods_remaining;

} HelloParser;


// Assumes pre-allocation
void hello_parser_init(HelloParser *p);

enum HelloState hello_parser_feed(HelloParser *p, uint8_t byte);

enum HelloState hello_parser_consume(Buffer *buffer, HelloParser *p, bool *errored);

bool hello_is_done(enum HelloState state, bool *errored);

// Reportar el problema

#endif