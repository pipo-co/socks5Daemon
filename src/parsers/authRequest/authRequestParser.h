#ifndef AUTH_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define AUTH_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

#include "buffer/buffer.h"

#define UINT8_STR_MAX_LENGTH 256

typedef enum AuthRequestParserState {
    AUTH_REQUEST_PARSER_VERSION,
    AUTH_REQUEST_PARSER_ULEN,
    AUTH_REQUEST_PARSER_UNAME,
    AUTH_REQUEST_PARSER_PLEN,
    AUTH_REQUEST_PARSER_PASSWORD,
    AUTH_REQUEST_PARSER_SUCCESS,
    AUTH_REQUEST_PARSER_INVALID_STATE,
} AuthRequestParserState;

typedef enum AuthRequestErrorType {
    AUTH_REQUEST_VALID,
    AUTH_REQUEST_INVALID_VERSION,
    AUTH_REQUEST_INVALID_ULEN,
    AUTH_REQUEST_INVALID_PLEN,
} AuthRequestErrorType;

typedef struct AuthRequestParser {

    uint8_t version;

    AuthRequestErrorType errorType;

    uint8_t ulen;

    char username[UINT8_STR_MAX_LENGTH];

    uint8_t plen;

    char password[UINT8_STR_MAX_LENGTH];

//  --- PRIVATE ---

    AuthRequestParserState currentState;

    uint8_t credentialCharPointer;

}AuthRequestParser;

void auth_request_parser_init(AuthRequestParser *p);

enum AuthRequestParserState auth_request_parser_feed(AuthRequestParser *p, uint8_t byte);

bool auth_request_parser_consume(Buffer *buffer, AuthRequestParser *p, bool *errored);

bool auth_request_parser_is_done(enum AuthRequestParserState state, bool *errored);

char * auth_request_parser_error_message(AuthRequestParser *p);

#endif