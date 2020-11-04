#include "requestSuccessful.h"

#define REPLY_SIZE 10

static void request_marshall(Buffer *b, size_t *bytes);
static void request_successful_on_arrival(SelectorEvent *event);
static unsigned request_successful_on_write(SelectorEvent *event);

static void request_successful_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.requestHeader.bytes = 0;

    request_marshall(&session->output, &session->socksHeader.requestHeader.bytes);  

    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
    selector_set_interest(event->s, session->serverConnection.fd, OP_NOOP);
}

static unsigned request_successful_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.requestHeader.bytes == REPLY_SIZE && !buffer_can_read(&session->output)) {
        return FORWARDING;
    }

    request_marshall(&session->output, &session->socksHeader.requestHeader.bytes); 

    return session->sessionStateMachine.current;
}

static void request_marshall(Buffer *b, size_t *bytes) {

        while(*bytes < REPLY_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, RESPONSE_SUCCESS_MESSAGE);
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

SelectorStateDefinition request_successful_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_SUCCESSFUL,
        .on_arrival = request_successful_on_arrival,
        .on_read = NULL,
        .on_write = request_successful_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}