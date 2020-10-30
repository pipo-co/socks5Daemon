

#include <stdio.h>
#include <stdlib.h>

#include "request.h"

void request_parser_init(RequestParser *p) {

    p->currentState = REQUEST_VERSION;
    p->addressLength = 0;
}

enum RequestState request_parser_feed(RequestParser *p, uint8_t b) {

    switch(p->currentState) {

        case REQUEST_VERSION:

            if(b == SOCKS_VERSION)
                p->currentState = REQUEST_COMMAND;

            else
                p->currentState = REQUEST_ERROR_UNSUPPORTED_VERSION;
        break;

        case REQUEST_COMMAND:

            if(b == REQUEST_COMMAND_CONNECT)
                p->currentState = REQUEST_RESERVED;

            else
                p->currentState = REQUEST_ERROR_UNSUPPORTED_CMD;
        break;

        case REQUEST_RESERVED:

            p->currentState = REQUEST_ADD_TYPE;
        break;

        case REQUEST_ADD_TYPE:

            p->addressType = b;

            if(b == REQUEST_ADD_TYPE_DOMAIN_NAME)
                p->currentState = REQUEST_DOMAIN_LENGTH;
            
            else if(b == REQUEST_ADD_TYPE_IP4) {
                p->addressLength = IP4_LENGTH;
                p->addressRemaining = IP4_LENGTH;
                p->currentState = REQUEST_ADDRESS;
                p->address[p->addressLength] = 0;
                
            }
            else if (b == REQUEST_ADD_TYPE_IP6) {
                p->addressLength = IP6_LENGTH;
                p->addressRemaining = IP6_LENGTH;
                p->currentState = REQUEST_ADDRESS;
                p->address[p->addressLength] = 0;

            }
            else
                p->currentState = REQUEST_ERROR_UNSUPPORTED_ADD_TYPE;
        break;

        case REQUEST_DOMAIN_LENGTH:

            p->addressLength = b;
            p->addressRemaining = b;

            // Domain Name Null Terminated
            p->address[p->addressLength] = 0;

            if(b > 0) 
                p->currentState = REQUEST_ADDRESS;

            else
                p->currentState = REQUEST_PORT_HIGH;
        break;

        case REQUEST_ADDRESS:

            p->address[p->addressLength - p->addressRemaining] = b;

            p->addressRemaining--;

            if(p->addressRemaining == 0)
                p->currentState = REQUEST_PORT_HIGH;
            
        break;

        case REQUEST_PORT_HIGH:

            p->port = b << PORT_LENGTH/2 * 8;

            p->currentState = REQUEST_PORT_LOW;

        break;

        case REQUEST_PORT_LOW:

            p->port += b;

            p->currentState = REQUEST_SUCCESS;

        break;

        case REQUEST_SUCCESS:
        case REQUEST_ERROR_UNSUPPORTED_VERSION:
        case REQUEST_ERROR_UNSUPPORTED_CMD:
        case REQUEST_ERROR_UNSUPPORTED_ADD_TYPE:
            // Nada que hacer
        break;

        default:
            fprintf(stderr, "Invalid state in request.c %d\n", p->currentState);
            abort();
        break;
    }

    return p->currentState;
}

enum RequestState request_parser_consume(Buffer *buffer, RequestParser *p, bool *errored) {

    uint8_t byte;

    while(!request_is_done(p->currentState, errored) && buffer_can_read(buffer)) {

        byte = buffer_read(buffer);
        request_parser_feed(p, byte); 
    }

    return p->currentState;
}

bool request_is_done(enum RequestState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {

        case REQUEST_ERROR_UNSUPPORTED_VERSION:
        case REQUEST_ERROR_UNSUPPORTED_CMD:
        case REQUEST_ERROR_UNSUPPORTED_ADD_TYPE:

            if(errored != NULL)
                *errored = true;

            return true;
        break;

        case REQUEST_SUCCESS:

            return true;
        break;

        case REQUEST_VERSION:
        case REQUEST_COMMAND:
        case REQUEST_RESERVED:
        case REQUEST_ADD_TYPE:
        case REQUEST_DOMAIN_LENGTH:
        case REQUEST_ADDRESS:
        case REQUEST_PORT_HIGH:
        case REQUEST_PORT_LOW:
        
            return false;
        break;

        default:
            fprintf(stderr, "Invalid state in request.c %d\n", state);
            abort();
        break;
    }
}