

#include <stdio.h>
#include <stdlib.h>

#include "hello.h"

void hello_parser_init(HelloParser *p) {

    p->current_state = HELLO_VERSION;
    p->methods_remaining = 0;
}

enum HelloState hello_parser_feed(HelloParser *p, uint8_t b) {

    switch(p->current_state) {

        case HELLO_VERSION:

            if(b == SOCKS_VERSION)
                p->current_state = HELLO_NMETHODS;

            else
                p->current_state = HELLO_ERROR_UNSUPPORTED_VERSION;
        break;

        case HELLO_NMETHODS:

            p->methods_remaining = b;

            if(b > 0) 
                p->current_state = HELLO_METHODS;

            else
                p->current_state = HELLO_DONE;
        break;

        case HELLO_METHODS:

            p->on_auth_method(p, b);

            p->methods_remaining--;

            if(p->methods_remaining == 0)
                p->current_state = HELLO_DONE;
        break;

        case HELLO_DONE:
            // Nada que hacer
        break;

        case HELLO_ERROR_UNSUPPORTED_VERSION:
        // Nada que hacer
        break;

        default:
            fprintf(stderr, "Invalid state in hello.c %d\n", p->current_state);
            abort();
        break;
    }

    return p->current_state;
}

enum HelloState hello_parser_consume(Buffer *buffer, HelloParser *p, bool *errored) {

    uint8_t byte;

    while(!hello_is_done(p->current_state, errored) && buffer_can_read(buffer)) {

        byte = buffer_read(buffer);
        hello_parser_feed(p, byte); 
    }

    return p->current_state;
}

bool hello_is_done(enum HelloState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {

        case HELLO_ERROR_UNSUPPORTED_VERSION:

            if(errored != NULL)
                *errored = true;

            return true;
        break;

        case HELLO_DONE:

            return true;
        break;

        case HELLO_VERSION:
        case HELLO_NMETHODS:
        case HELLO_METHODS:
        
            return false;
        break;

        default:
            fprintf(stderr, "Invalid state in hello.c %d\n", state);
            abort();
        break;
    }
}