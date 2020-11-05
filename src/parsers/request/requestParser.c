#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "requestParser.h"

void request_parser_init(RequestParser *p) {

    memset(p, '\0', sizeof(*p));
    p->currentState = REQUEST_PARSER_VERSION;
}

enum RequestParserState request_parser_feed(RequestParser *p, uint8_t b) {

    switch(p->currentState) {

        case REQUEST_PARSER_VERSION:

            p->version = b;
            
            p->currentState = REQUEST_PARSER_COMMAND;
        break;

        case REQUEST_PARSER_COMMAND:

            p->cmd = b;

            p->currentState = REQUEST_PARSER_RESERVED;
        break;

        case REQUEST_PARSER_RESERVED:
            //TODO se hace algo si esta no reserved
            p->currentState = REQUEST_PARSER_ADD_TYPE;
        break;

        case REQUEST_PARSER_ADD_TYPE:

            p->addressType = b;

            if(b == REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME){
                p->currentState = REQUEST_PARSER_DOMAIN_LENGTH;
            } 
            else if(b == REQUEST_PARSER_ADD_TYPE_IP4) {
                p->addressRemaining = IP4_LENGTH;
                p->currentState = REQUEST_PARSER_IPV4_ADDRESS;
            } 
            else if (b == REQUEST_PARSER_ADD_TYPE_IP6) {
                p->addressRemaining = p->addressLength = IP6_LENGTH;
                p->currentState = REQUEST_PARSER_IPV6_ADDRESS;
            }
            else
                p->currentState = REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE;
        break;

        case REQUEST_PARSER_DOMAIN_LENGTH:

            p->addressRemaining = p->addressLength = b;

            // Domain Name Null Terminated
            p->address.domainName[p->addressRemaining] = 0;

            if(b > 0) 
                p->currentState = REQUEST_PARSER_DOMAIN_ADDRESS;

            else
                p->currentState = REQUEST_PARSER_PORT_HIGH;
        break;

        case REQUEST_PARSER_DOMAIN_ADDRESS:

            p->address.domainName[p->addressLength - p->addressRemaining] = b;

            p->addressRemaining--;

            if(p->addressRemaining == 0)
                p->currentState = REQUEST_PARSER_PORT_HIGH;
            
        break;

        case REQUEST_PARSER_IPV4_ADDRESS:

            p->address.ipv4.s_addr = (p->address.ipv4.s_addr << 8) + b;

            p->addressRemaining--;

            if(p->addressRemaining == 0){
                p->address.ipv4.s_addr = htonl(p->address.ipv4.s_addr);
                p->currentState = REQUEST_PARSER_PORT_HIGH;
            }
            
        break;

        case REQUEST_PARSER_IPV6_ADDRESS:

            p->address.ipv6.s6_addr[p->addressLength - p->addressRemaining] = b;

            p->addressRemaining--;

            if(p->addressRemaining == 0){
               p->currentState = REQUEST_PARSER_PORT_HIGH;
            }
            
        break;

        case REQUEST_PARSER_PORT_HIGH:

            p->port = b << 8;

            p->currentState = REQUEST_PARSER_PORT_LOW;

        break;

        case REQUEST_PARSER_PORT_LOW:

            p->port += b;
            p->port = htons(p->port);
            p->currentState = REQUEST_PARSER_DONE;

        break;

        case REQUEST_PARSER_DONE:
        case REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE:
        case REQUEST_PARSER_ERROR_INVALID_STATE:
            // Nada que hacer
        break;

        default:
            p->currentState = REQUEST_PARSER_ERROR_INVALID_STATE;
        break;
    }

    return p->currentState;
}

bool request_parser_consume(Buffer *buffer, RequestParser *p, bool *errored) {

    uint8_t byte;

    while(!request_parser_is_done(p->currentState, errored) && buffer_can_read(buffer)) {

        byte = buffer_read(buffer);
        request_parser_feed(p, byte); 
    }

    return request_parser_is_done(p->currentState, errored);
}

bool request_parser_is_done(enum RequestParserState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {

        case REQUEST_PARSER_DONE:

            return true;
        break;

        case REQUEST_PARSER_VERSION:
        case REQUEST_PARSER_COMMAND:
        case REQUEST_PARSER_RESERVED:
        case REQUEST_PARSER_ADD_TYPE:
        case REQUEST_PARSER_DOMAIN_LENGTH:
        case REQUEST_PARSER_DOMAIN_ADDRESS:
        case REQUEST_PARSER_IPV4_ADDRESS:
        case REQUEST_PARSER_IPV6_ADDRESS:
        case REQUEST_PARSER_PORT_HIGH:
        case REQUEST_PARSER_PORT_LOW:
        
            return false;
        break;

        case REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE:
        case REQUEST_PARSER_ERROR_INVALID_STATE:
        default:

            if(errored != NULL)
                *errored = true;

            return true;
        break;
    }
}

char * request_parser_error_message(enum RequestParserState state){
    switch(state) {

        case REQUEST_PARSER_DONE:
        case REQUEST_PARSER_VERSION:
        case REQUEST_PARSER_COMMAND:
        case REQUEST_PARSER_RESERVED:
        case REQUEST_PARSER_ADD_TYPE:
        case REQUEST_PARSER_DOMAIN_LENGTH:
        case REQUEST_PARSER_DOMAIN_ADDRESS:
        case REQUEST_PARSER_IPV4_ADDRESS:
        case REQUEST_PARSER_IPV6_ADDRESS:
        case REQUEST_PARSER_PORT_HIGH:
        case REQUEST_PARSER_PORT_LOW:
        
            return "Request: no error";
        break;

        case REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE:

            return "Request: Unsupported address type!";

        break;

        case REQUEST_PARSER_ERROR_INVALID_STATE:
        default:

            return "Request: Invalid state";
        break;
    }
        
}