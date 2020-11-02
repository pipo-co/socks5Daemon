#ifndef AUTH_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define AUTH_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

#include "buffer/buffer.h"
#define PARAMETER_MAX_SIZE 255

enum AuthRequestParserState {
    AUTH_REQUEST_PARSER_VERSION,
    AUTH_REQUEST_PARSER_ULEN,
    AUTH_REQUEST_PARSER_UNAME,
    AUTH_REQUEST_PARSER_PLEN,
    AUTH_REQUEST_PARSER_PASSWORD,
    AUTH_REQUEST_PARSER_INVALID_STATE,
};

typedef struct AuthRequestParser {

    void *data;

    uint8_t version;

    uint8_t ulen;

    char username[PARAMETER_MAX_SIZE];

    uint8_t plen;

    char password[PARAMETER_MAX_SIZE];

    enum AuthRequestParserState current_state;

}AuthRequestParser;

void auth_request_parser_init(AuthRequestParser *p);

enum AuthRequestParserState auth_request_parser_feed(AuthRequestParser *p, uint8_t byte);

bool auth_request_parser_consume(Buffer *buffer, AuthRequestParser *p, bool *errored);

bool auth_request_parser_is_done(enum AuthRequestParserState state, bool *errored);

char * auth_request_parser_error_message(enum AuthRequestParserState state);

#endif