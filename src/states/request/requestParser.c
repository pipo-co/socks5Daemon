#include <stdio.h>
#include <stdlib.h>

#include "requestParser.h"

void REQUEST_PARSER_parser_init(RequestParser *p) {

    p->currentState = REQUEST_PARSER_VERSION;
    p->addressLength = 0;
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

            p->currentState = REQUEST_PARSER_ADD_TYPE;
        break;

        case REQUEST_PARSER_ADD_TYPE:

            p->addressType = b;

            if(b == REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME)
                p->currentState = REQUEST_PARSER_DOMAIN_LENGTH;
            
            else if(b == REQUEST_PARSER_ADD_TYPE_IP4) {
                p->addressLength = IP4_LENGTH;
                p->addressRemaining = IP4_LENGTH;
                p->currentState = REQUEST_PARSER_IPV4_ADDRESS;
                p->address[p->addressLength] = 0;
                
            }
            else if (b == REQUEST_PARSER_ADD_TYPE_IP6) {
                p->addressLength = IP6_LENGTH;
                p->addressRemaining = IP6_LENGTH;
                p->currentState = REQUEST_PARSER_IPV6_ADDRESS;
                p->address[p->addressLength] = 0;

            }
            else
                p->currentState = REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE;
        break;

        case REQUEST_PARSER_DOMAIN_LENGTH:

            p->addressLength = b;
            p->addressRemaining = b;

            // Domain Name Null Terminated
            p->address[p->addressLength] = 0;

            if(b > 0) 
                p->currentState = REQUEST_PARSER_DOMAIN_ADDRESS;

            else
                p->currentState = REQUEST_PARSER_PORT_HIGH;
        break;

        case REQUEST_PARSER_DOMAIN_ADDRESS:

            p->address[p->addressLength - p->addressRemaining] = b;

            p->addressRemaining--;

            if(p->addressRemaining == 0)
                p->currentState = REQUEST_PARSER_PORT_HIGH;
            
        break;

        case REQUEST_PARSER_IPV4_ADDRESS:

            sprintf(p->address + (p->addressLength - p->addressRemaining), "%03d", b);

            p->addressRemaining -= 3;

            if(p->addressRemaining != 0){
                p->address[p->addressLength - p->addressRemaining] = '.';
                p->addressRemaining--;
            }

            if(p->addressRemaining == 0)
                p->currentState = REQUEST_PARSER_PORT_HIGH;
            
        break;

        case REQUEST_PARSER_IPV6_ADDRESS:

            sprintf(p->address + (p->addressLength - p->addressRemaining), "%02x", b);

            p->addressRemaining -= 2;

            if((p->addressLength - p->addressRemaining) % 5 == 4 && p->addressRemaining != 0){

                p->address[p->addressLength - p->addressRemaining] = ':';
                p->addressRemaining--;
            }

            if(p->addressRemaining == 0)
                p->currentState = REQUEST_PARSER_PORT_HIGH;
            
        break;

        case REQUEST_PARSER_PORT_HIGH:

            p->port = b << 8;

            p->currentState = REQUEST_PARSER_PORT_LOW;

        break;

        case REQUEST_PARSER_PORT_LOW:

            p->port += b;

            p->currentState = REQUEST_PARSER_SUCCESS;

        break;

        case REQUEST_PARSER_SUCCESS:
        case REQUEST_PARSER_ERROR_UNSUPPORTED_ADD_TYPE:
        case REQUEST_PARSER_INVALID_STATE:
            // Nada que hacer
        break;

        default:
            p->currentState = REQUEST_PARSER_INVALID_STATE;
        break;
    }

    return p->currentState;
}

bool request_parser_parser_consume(Buffer *buffer, RequestParser *p, bool *errored) {

    uint8_t byte;

    while(!request_parser_is_done(p->currentState, errored) && buffer_can_read(buffer)) {

        byte = buffer_read(buffer);
        request_parser_parser_feed(p, byte); 
    }

    return hello_is_done(p->currentState, errored);
}

bool request_parser_is_done(enum RequestParserState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {

        case REQUEST_PARSER_SUCCESS:

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
        case REQUEST_PARSER_INVALID_STATE:
        default:

            if(errored != NULL)
                *errored = true;

            return true;
        break;
    }
}

char * request_parser_error_message(enum RequestParserState state){
    switch(state) {

        case REQUEST_PARSER_SUCCESS:
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

        case REQUEST_PARSER_INVALID_STATE:
        default:

            return "Request: Invalid state";
        break;
    }
        
}