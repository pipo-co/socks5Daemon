#ifndef HELLO_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define HELLO_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

#include "buffer/buffer.h"


enum HelloParserState {
    HELLO_PARSER_VERSION,
    HELLO_PARSER_NMETHODS,
    HELLO_PARSER_METHODS,
    HELLO_PARSER_DONE,
    HELLO_PARSER_INVALID_STATE,
    HELLO_PARSER_INVALID_AUTH_METHOD_STATE,
};

// Not an ADT to avoid unnecessary usages of malloc
typedef struct HelloParser {
    bool (*on_auth_method)(struct HelloParser *parser, uint8_t method);

    void *data;

    uint8_t version;

    enum HelloParserState current_state;

    uint8_t methods_remaining;

}HelloParser;


// Assumes pre-allocation
void hello_parser_init(HelloParser *p, bool (*on_auth_method)(HelloParser *p, uint8_t currentMethod), void * data);

enum HelloParserState hello_parser_feed(HelloParser *p, uint8_t byte);

bool hello_parser_consume(Buffer *buffer, HelloParser *p, bool *errored);

bool hello_parser_is_done(enum HelloParserState state, bool *errored);

char * hello_parser_error_message(enum HelloParserState state);

// Reportar el problema

#endif