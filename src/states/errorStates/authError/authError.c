#include "authError.h"

#define AUTH_ERROR_REPLY_SIZE 2

static void auth_error_marshall(Buffer *b, size_t *bytes);
static void auth_error_on_arrival(SelectorEvent *event);
static unsigned auth_error_on_write(SelectorEvent *event);

static void auth_error_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.authRequestHeader.bytes = 0;

    /* Primer escritura del mensaje antes de hacerle el primer send al cliente */
    auth_error_marshall(&session->output, &session->socksHeader.authRequestHeader.bytes);  
    
    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
}

/* Una vez que envie el mensaje de error me voy al estado finnish que se ocupara de liberar los recursos de mi session */
static unsigned auth_error_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.authRequestHeader.bytes == AUTH_ERROR_REPLY_SIZE && !buffer_can_read(&session->output)) {
        return FINISH;
    }
    
    auth_error_marshall(&session->output, &session->socksHeader.authRequestHeader.bytes);

    return session->sessionStateMachine.current;
}

static void auth_error_marshall(Buffer *b, size_t *bytes) {

    while(*bytes < AUTH_ERROR_REPLY_SIZE && buffer_can_write(b)){
        if(*bytes == 0){
            buffer_write(b, SOCKS_VERSION);
        }
        if(*bytes == 1){
            buffer_write(b, AUTH_UNSUCCESSFUL_MESSAGE);
        }
        (*bytes)++;
    }
}


SelectorStateDefinition auth_error_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_ERROR,
        .on_arrival = auth_error_on_arrival,
        .on_read = NULL,
        .on_write = auth_error_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
