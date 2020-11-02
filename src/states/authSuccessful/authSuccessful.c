#include "authSuccessful.h"

#define AUTH_RESPONSE_SIZE 2

static int auth_marshall(Buffer *b, uint8_t *bytes);
static unsigned auth_successful_on_pre_write(SelectorEvent *event);
static unsigned auth_successful_on_post_write(SelectorEvent *event);
static void auth_successful_on_departure(SelectorEvent *event);

static int auth_marshall(Buffer *b, uint8_t *bytes) {

        while(*bytes < AUTH_RESPONSE_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            if(*bytes == 1){
                buffer_write(b, AUTH_SUCCESS_MESSAGE);
            }
            *bytes++;
        }
    }

static unsigned auth_successful_on_pre_write(SelectorEvent *event) {
    
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    auth_marshall(&socks5_p->output, socks5_p->socksHeader.authRequestHeader.bytes);  
    
    return socks5_p->sessionStateMachine.current; 
}

static unsigned auth_successful_on_post_write(SelectorEvent *event) {

     SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    if (socks5_p->socksHeader.authRequestHeader.bytes == AUTH_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_set_interest_event(event, OP_READ);
        return REQUEST;
    }
    return socks5_p->sessionStateMachine.current;
}

static void auth_successful_on_departure(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    //depende de como manejemos la memoria tendriamos que liberar la estructura

}

SelectorStateDefinition auth_successful_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_SUCCESSFUL,
        .on_arrival = NULL,
        .on_post_read = NULL,
        .on_pre_write = auth_successful_on_pre_write,
        .on_post_write = auth_successful_on_post_write,
        .on_block_ready = NULL,
        .on_departure = auth_successful_on_departure,
    };

    return stateDefinition;
}