#include "authError.h"

#define AUTH_ERROR_RESPONSE_SIZE 2

static int auth_error_marshall(Buffer *b, uint8_t *bytes);
static unsigned auth_error_on_pre_write(SelectorEvent *event);
static unsigned auth_error_on_post_write(SelectorEvent *event);

static int auth_error_marshall(Buffer *b, uint8_t *bytes) {

        while(*bytes < AUTH_ERROR_RESPONSE_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            if(*bytes == 1){
                buffer_write(b, AUTH_UNSUCCESSFUL_MESSAGE);
            }
            *bytes++;
        }
    }

static unsigned auth_error_on_pre_write(SelectorEvent *event) {
    
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    auth_error_marshall(&socks5_p->output, socks5_p->socksHeader.authRequestHeader.bytes);  
    
    return socks5_p->sessionStateMachine.current; 

}

static unsigned auth_error_on_post_write(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    if (socks5_p->socksHeader.authRequestHeader.bytes == AUTH_ERROR_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_unregister_fd(event->s, event->fd);
        return FINISH;
    }
    return socks5_p->sessionStateMachine.current;

}

SelectorStateDefinition auth_error_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_ERROR,
        .on_arrival = NULL,
        .on_post_read = NULL,
        .on_pre_write = auth_error_on_pre_write,
        .on_post_write = auth_error_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}