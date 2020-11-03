#include "requestError.h"

#define REQUEST_ERROR_SIZE 10

static void request_error_marshall(Buffer *b, size_t *bytes, uint8_t rep);
static unsigned request_error_on_pre_write(SelectorEvent *event);
static unsigned request_error_on_post_write(SelectorEvent *event);

static unsigned request_error_on_pre_write(SelectorEvent *event) {
    
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    request_error_marshall(&socks5_p->output, &socks5_p->socksHeader.requestHeader.bytes, socks5_p->socksHeader.requestHeader.rep);  
    
    return socks5_p->sessionStateMachine.current; 

}

static unsigned request_error_on_post_write(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    if (socks5_p->socksHeader.requestHeader.bytes == REQUEST_ERROR_SIZE && !buffer_can_read(&socks5_p->output)) {
        selector_unregister_fd(event->s, event->fd);
        return FINISH;
    }

    return socks5_p->sessionStateMachine.current;
}

static void request_error_marshall(Buffer *b, size_t *bytes, uint8_t rep) {

        while(*bytes < REQUEST_ERROR_SIZE && buffer_can_write(b)) {
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, rep);
            }
            else if (*bytes == 2){
                buffer_write(b, RSV);
            }
            else if (*bytes == 3){
                buffer_write(b, ATYP);
            }
            else {
                buffer_write(b, 0);
            }
            (*bytes)++;
        }
    }

SelectorStateDefinition request_error_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_ERROR,
        .on_arrival = NULL,
        .on_post_read = NULL,
        .on_pre_write = request_error_on_pre_write,
        .on_post_write = request_error_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}