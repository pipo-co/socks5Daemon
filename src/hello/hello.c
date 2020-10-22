

#include <stdio.h>
#include <stdlib.h>

#include "hello.h"

void helloParserInit(HelloParser *p) {

    p->current_state = hello_version;
    p->methods_remaining = 0;
}

enum HelloState helloParserFeed(HelloParser *p, uint8_t b) {

    switch(p->current_state) {

        case hello_version:

            if(b == SOCKS_VERSION)
                p->current_state = hello_nmethods;

            else
                p->current_state = hello_error_unsupported_version;
        break;

        case hello_nmethods:

            p->methods_remaining = b;

            if(b > 0) 
                p->current_state = hello_methods;

            else
                p->current_state = hello_done;
        break;

        case hello_methods:

            p->onAuthMethod(p, b);

            p->methods_remaining--;

            if(p->methods_remaining == 0)
                p->current_state = hello_done;
        break;

        case hello_done:
            // Nada que hacer
        break;

        case hello_error_unsupported_version:
        // Nada que hacer
        break;

        default:
            fprintf(stderr, "Invalid state %d\n", p->current_state);
            abort();
        break;
    }

    return p->current_state;
}

enum HelloState helloParserConsume(buffer *buffer, HelloParser *p, bool *errored) {

    uint8_t byte;

    while(helloIsDone(p, errored) && buffer_can_read(buffer)) {

        byte = buffer_read(buffer);
        helloParserFeed(p, byte); 
    }

    return p->current_state;
}

bool helloIsDone(enum HelloState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {

        case hello_error_unsupported_version:

            if(errored != NULL)
                *errored = true;

            return true;
        break;

        case hello_done:

            return true;
        break;

        case hello_version:
        case hello_nmethods:
        case hello_methods:
        
            return false;
        break;

        default:
            fprintf(stderr, "Invalid state %d\n", state);
            abort();
        break;
    }
}