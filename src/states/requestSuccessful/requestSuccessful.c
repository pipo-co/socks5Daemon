#include "requestSuccessful.h"

#define REPLY_SIZE 10

static int request_marshall(Buffer *b, uint8_t *bytes);
static unsigned request_successful_on_pre_write(SelectorEvent *event);
static unsigned request_successful_on_post_write(SelectorEvent *event);
static void request_successful_on_departure(SelectorEvent *event);

static int request_marshall(Buffer *b, uint8_t *bytes) {

        while(*bytes < REPLY_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, AUTH_SUCCESS_MESSAGE);
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
            *bytes++;
        }
    }

static unsigned request_successful_on_pre_write(SelectorEvent *event) {
    
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    request_marshall(&socks5_p->output, socks5_p->socksHeader.requestHeader.bytes);  

    return socks5_p->sessionStateMachine.current; 

}

static unsigned request_successful_on_post_write(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    if (socks5_p->socksHeader.requestHeader.bytes == REPLY_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_set_interest(event->s, socks5_p->serverConnection.fd, OP_READ|OP_WRITE);
        selector_set_interest_event(event, OP_READ|OP_WRITE);
        return FINISH; // TODO: FORWARDING;
    }
    return socks5_p->sessionStateMachine.current;

}

static void request_successful_on_departure(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    //depende de como manejemos la memoria tendriamos que liberar la estructura

}

SelectorStateDefinition request_successful_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_SUCCESSFUL,
        .on_arrival = NULL,
        .on_post_read = request_successful_on_post_write,
        .on_pre_write = request_successful_on_pre_write,
        .on_post_write = NULL,
        .on_block_ready = NULL,
        .on_departure = request_successful_on_departure,
    };

    return stateDefinition;
}