#ifndef HTTP_DNS_PARSER_H_237cf11b918a97e16402b064e7e5af5cd7f70661
#define HTTP_DNS_PARSER_H_237cf11b918a97e16402b064e7e5af5cd7f70661

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#define STATUS_CODE 3

#include "buffer/buffer.h"

typedef enum HttpDnsParserState{
    HTTP_STATUS_CODE_FIRST,
    HTTP_CONTENT_LENGTH,
    HTTP_CONTENT_LENGTH_NUMBER,
    HTTP_CONTENT_LENGTH_FINISH,
    HTTP_SECOND_LINE,
    HTTP_LAST_CHARACTER,
    HTTP_PAYLOAD_DELIMITER,
    HTTP_DNS_DONE,
    HTTP_DNS_ERROR,
}HttpDnsParserState;

typedef struct HttpDnsParser {

    uint8_t contentLenght;
    enum HttpDnsParserState currentState;

}HttpDnsParser;

void http_dns_parser_init(HttpDnsParser *p);

enum HttpDnsParserState http_dns_parser_feed(HttpDnsParser *p, uint8_t b);

bool http_dns_parser_consume(Buffer *buffer, HttpDnsParser *p, bool *errored);

bool http_dns_parser_is_done(enum HttpDnsParserState state, bool *errored);

// char * http_dns_parser_error_message(enum HttpDnsParserState state);

#endif