#include "helloError.h"

#define HELLO_ERROR_RESPONSE_SIZE 2

static void hello_error_marshall(Buffer *b, size_t *bytes);
static unsigned hello_error_on_pre_write(SelectorEvent *event);
static unsigned hello_error_on_post_write(SelectorEvent *event);

static unsigned hello_error_on_pre_write(SelectorEvent *event) {
    
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    hello_error_marshall(&socks5_p->output, &socks5_p->socksHeader.helloHeader.bytes);  
    
    return socks5_p->sessionStateMachine.current; 

}

static unsigned hello_error_on_post_write(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    if (socks5_p->socksHeader.helloHeader.bytes == HELLO_ERROR_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_unregister_fd(event->s, event->fd);
        return FINISH;
    }
    return socks5_p->sessionStateMachine.current;

}

static void hello_error_marshall(Buffer *b, size_t *bytes) {

        while(*bytes < HELLO_ERROR_RESPONSE_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            if(*bytes == 1){
                buffer_write(b, NO_ACCEPTABLE_METHODS);
            }
            (*bytes)++;
        }
    }


SelectorStateDefinition hello_error_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = HELLO_ERROR,
        .on_arrival = NULL,
        .on_post_read = NULL,
        .on_pre_write = hello_error_on_pre_write,
        .on_post_write = hello_error_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}