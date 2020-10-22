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
    hello_version,
    hello_nmethods,
    hello_methods,
    hello_done,
    hello_error_unsupported_version,
};

// Not an ADT to avoid unnecessary usages of malloc
typedef struct HelloParser {
    void (*onAuthMethod)(struct HelloParser *parser, uint8_t method);

    void *data;

    enum HelloState current_state;

    uint8_t methods_remaining;

} HelloParser;


// Assumes pre-allocation
void helloParserInit(HelloParser *p);

enum HelloState helloParserFeed(HelloParser *p, uint8_t byte);

enum HelloState helloParserConsume(buffer *buffer, HelloParser *p, bool *errored);

bool helloIsDone(enum HelloState state, bool *errored);

// Reportar el problema

#endif