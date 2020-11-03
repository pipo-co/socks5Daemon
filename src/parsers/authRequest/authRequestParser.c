#include "authRequestParser.h"
#include <string.h>

void auth_request_parser_init(AuthRequestParser *p){
    memset(p, '\0', sizeof(*p));
}

enum AuthRequestParserState auth_request_parser_feed(AuthRequestParser *p, uint8_t byte){
    if(p == NULL || byte == 0)
        return AUTH_REQUEST_PARSER_INVALID_STATE;
    return AUTH_REQUEST_PARSER_PASSWORD;
}

bool auth_request_parser_consume(Buffer *buffer, AuthRequestParser *p, bool *errored){
    if(buffer == NULL || p == NULL || errored == NULL)
        return false;
    return true;
}

bool auth_request_parser_is_done(enum AuthRequestParserState state, bool *errored){
    if(state != AUTH_REQUEST_PARSER_VERSION || errored == NULL)
        return false;
    return true;
}

char * auth_request_parser_error_message(enum AuthRequestParserState state){
    if(state != AUTH_REQUEST_PARSER_VERSION)
        return "Yet not implemenetd";
    
    return "Not implemented Yet!";
}
