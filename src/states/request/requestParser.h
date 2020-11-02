#ifndef REQUEST_H_237cf11b918a97e16402b064e7e5af5cd7f70661
#define REQUEST_H_237cf11b918a97e16402b064e7e5af5cd7f70661

#include <stdint.h>
#include <stdbool.h>

#include "../buffer/buffer.h"

#define DOMAIN_NAME_MAX_LENGTH 255
#define IP4_LENGTH 15 // 3 * 4 + 3
#define IP6_LENGTH 39 // 4 * 8 + 7

#define REQUEST_ADDRESS_MAX_LENGTH (DOMAIN_NAME_MAX_LENGTH + 1)

#define SOCKS_VERSION 0x05

// Valid Commands
#define REQUEST_PARSER_COMMAND_CONNECT 0x01

// Valid Address Type
typedef enum { REQUEST_PARSER_ADD_TYPE_IP4 = 0x01, REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME = 0x03 , REQUEST_PARSER_ADD_TYPE_IP6 = 0x04
}RequestIpEnum;


enum RequestParserState {
    REQUEST_PARSER_VERSION,
    REQUEST_PARSER_COMMAND,
    REQUEST_PARSER_RESERVED,
    REQUEST_PARSER_ADD_TYPE,
    REQUEST_PARSER_DOMAIN_LENGTH,
    REQUEST_PARSER_DOMAIN_ADDRESS,
    REQUEST_PARSER_IPV4_ADDRESS,
    REQUEST_PARSER_IPV6_ADDRESS,
    REQUEST_PARSER_PORT_HIGH,
    REQUEST_PARSER_PORT_LOW,
    REQUEST_PARSER_SUCCESS,
    REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE,
    REQUEST_PARSER_INVALID_STATE,
};

// Not an ADT to avoid unnecessary usages of malloc
typedef struct RequestParser {

    uint8_t version;

    uint8_t cmd;

    uint8_t addressType;

    uint8_t addressLength;

    uint8_t address[REQUEST_ADDRESS_MAX_LENGTH];

    uint16_t port;

    // --- Private attributes ---
    enum RequestParserState currentState;

    uint8_t addressRemaining;

} RequestParser;


// Assumes pre-allocation
void request_parser_init(RequestParser *p);

enum RequestParserState request_parser_feed(RequestParser *p, uint8_t byte);

bool request_parser_consume(Buffer *buffer, RequestParser *p, bool *errored);

bool request_is_done(enum RequestParserState state, bool *errored);

char * request_parser_error_message(enum RequestParserState state);
// Reportar el problema

#endif