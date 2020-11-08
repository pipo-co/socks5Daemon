#include "authSuccessful.h"

#include "statistics/statistics.h"

#define AUTH_REPLY_SIZE 2

static void auth_marshall(Buffer *b, size_t *bytes);
static void auth_successful_on_arrival(SelectorEvent *event);
static unsigned auth_successful_on_write(SelectorEvent *event);


static void auth_successful_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.authRequestHeader.bytes = 0;

    auth_marshall(&session->output, &session->socksHeader.authRequestHeader.bytes);  
    
    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
}

static unsigned auth_successful_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.authRequestHeader.bytes == AUTH_REPLY_SIZE && !buffer_can_read(&session->output)) {
        return REQUEST;
    }

    auth_marshall(&session->output, &session->socksHeader.authRequestHeader.bytes); 

    return session->sessionStateMachine.current;
}

static void auth_marshall(Buffer *b, size_t *bytes) {

    while(*bytes < AUTH_REPLY_SIZE && buffer_can_write(b)){
        if(*bytes == 0){
            buffer_write(b, SOCKS_VERSION);
        }
        if(*bytes == 1){
            buffer_write(b, AUTH_SUCCESS_MESSAGE);
        }
        (*bytes)++;
    }
}

SelectorStateDefinition auth_successful_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_SUCCESSFUL,
        .on_arrival = auth_successful_on_arrival,
        .on_read = NULL,
        .on_write = auth_successful_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}