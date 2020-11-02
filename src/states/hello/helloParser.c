#include <stdio.h>
#include <stdlib.h>

#include "helloParser.h"


void hello_parser_init(HelloParser *p, void (*on_auth_method)(HelloParser *p, uint8_t currentMethod), void * data) {

    p->current_state = HELLO_PARSER_VERSION;
    p->on_auth_method = on_auth_method;
    p->data = data;
    p->methods_remaining = 0;
}

enum HelloParserState hello_parser_feed(HelloParser *p, uint8_t b) {

    switch(p->current_state) {

        case HELLO_PARSER_VERSION:

            p->version = b;

            p->current_state = HELLO_PARSER_NMETHODS;
        break;

        case HELLO_PARSER_NMETHODS:

            p->methods_remaining = b;

            if(b > 0) 
                p->current_state = HELLO_PARSER_METHODS;

            else
                p->current_state = HELLO_PARSER_DONE;
        break;

        case HELLO_PARSER_METHODS:
           
            p->on_auth_method(p, b);
            
            p->methods_remaining--;

            if(p->methods_remaining == 0)
                p->current_state = HELLO_PARSER_DONE;
        break;

        case HELLO_PARSER_DONE:
            // Nothing to do
        break;

        case HELLO_PARSER_INVALID_STATE:
            // Nothing to do
        break;

        default:
            p->current_state = HELLO_PARSER_INVALID_STATE;
        break;
    }

    return p->current_state;
}

bool hello_parser_consume(Buffer *buffer, HelloParser *p, bool *errored) {

    uint8_t byte;

    while(!hello_parser_is_done(p->current_state, errored) && buffer_can_read(buffer)) {
        
        byte = buffer_read(buffer);
        hello_parser_feed(p, byte); 
    }

    return hello_parser_is_done(p->current_state, errored);
}

bool hello_parser_is_done(enum HelloParserState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {
        case HELLO_PARSER_DONE:

            return true;
        break;

        case HELLO_PARSER_VERSION:
        case HELLO_PARSER_NMETHODS:
        case HELLO_PARSER_METHODS:
        
            return false;
        break;

        case HELLO_PARSER_INVALID_STATE:
        default:
            if(errored != NULL)
                *errored = true;

            return true;
        break;
    }
}

char * hello_parser_error_message(enum HelloParserState state){
    switch(state) {
        case HELLO_PARSER_DONE:
        case HELLO_PARSER_VERSION:
        case HELLO_PARSER_NMETHODS:
        case HELLO_PARSER_METHODS:
        
            return "Hello parser: no error";
        break;
        case HELLO_PARSER_INVALID_STATE:
        default:
            return "Hello parser: Reached invalid state!";
        break;
    }
        
}

