#ifndef REQUEST_PARSER_H_237cf11b918a97e16402b064e7e5af5cd7f70661
#define REQUEST_PARSER_H_237cf11b918a97e16402b064e7e5af5cd7f70661

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "buffer/buffer.h"
#include "socksDefs.h"

// Valid Commands
#define REQUEST_PARSER_COMMAND_CONNECT 0x01

typedef enum RequestParserState {
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
    REQUEST_PARSER_DONE,
    REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE,
    REQUEST_PARSER_ERROR_INVALID_STATE,
} RequestParserState;

typedef union RequestParserAddress {

    uint8_t domainName[DOMAIN_NAME_MAX_LENGTH];
    struct in_addr ipv4; 
    struct in6_addr ipv6; 
} RequestParserAddress;

// Not an ADT to avoid unnecessary usages of malloc
typedef struct RequestParser {

    uint8_t version;

    uint8_t cmd;

    Socks5AddressTypes addressType;

    union RequestParserAddress address;

    in_port_t port;

    // --- Private attributes ---
    enum RequestParserState currentState;

    uint8_t addressRemaining;

    uint8_t addressLength;

} RequestParser;

// Assumes pre-allocation
void request_parser_init(RequestParser *p);

enum RequestParserState request_parser_feed(RequestParser *p, uint8_t byte);

bool request_parser_consume(Buffer *buffer, RequestParser *p, bool *errored);

bool request_parser_is_done(enum RequestParserState state, bool *errored);

char * request_parser_error_message(enum RequestParserState state);
// Reportar el problema

#endif
