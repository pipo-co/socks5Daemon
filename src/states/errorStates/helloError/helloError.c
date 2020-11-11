#include "helloError.h"

#define HELLO_ERROR_REPLY_SIZE 2

static void hello_error_marshall(Buffer *b, size_t *bytes);
static void hello_error_on_arrival(SelectorEvent *event);
static unsigned hello_error_on_write(SelectorEvent *event);

static void hello_error_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.helloHeader.bytes = 0;

    /* Primer escritura del mensaje antes de hacerle el primer send al cliente */
    hello_error_marshall(&session->output, &session->socksHeader.helloHeader.bytes);

    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
}

/* Una vez que envie el mensaje de error me voy al estado finnish que se ocupara de liberar los recursos de mi session */
static unsigned hello_error_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if (session->socksHeader.helloHeader.bytes == HELLO_ERROR_REPLY_SIZE && !buffer_can_read(&session->output)) {
        return FINISH;
    }

    hello_error_marshall(&session->output, &session->socksHeader.helloHeader.bytes);

    return session->sessionStateMachine.current;
}

static void hello_error_marshall(Buffer *b, size_t *bytes) {

        while(*bytes < HELLO_ERROR_REPLY_SIZE && buffer_can_write(b)){
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
        .on_arrival = hello_error_on_arrival,
        .on_read = NULL,
        .on_write = hello_error_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}