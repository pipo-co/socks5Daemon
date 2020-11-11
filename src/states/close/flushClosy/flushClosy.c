#include "flushClosy.h"

static unsigned flush_closy_on_write(SelectorEvent *event);
static void flush_closy_on_arrival(SelectorEvent *event);


static void flush_closy_on_arrival(SelectorEvent *event) {
    flush_closy_on_write(event);
}

static unsigned flush_closy_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    int clientFd = session->clientConnection.fd;
    int serverFd = session->serverConnection.fd;

    SocketState *clientState = &session->clientConnection.state;
    SocketState *serverState = &session->serverConnection.state;

    Buffer clientBuffer = session->input;
    Buffer serverBuffer = session->output;

    if(buffer_can_read(&clientBuffer)) {
        selector_set_interest(event->s, serverFd, OP_WRITE);
    }
    else {
        if(*clientState == CLOSING) {
            shutdown(serverFd, SHUT_WR);
            *clientState = CLOSED;
        }
        selector_set_interest(event->s, serverFd, OP_NOOP);
    }

    if(buffer_can_read(&serverBuffer)) {
        selector_set_interest(event->s, clientFd, OP_WRITE);
    }
    else {
        if(*serverState == CLOSING) {
            shutdown(clientFd, SHUT_WR);
            *serverState = CLOSED;
        }
        selector_set_interest(event->s, clientFd, OP_NOOP);
    }
    /* Cuando finalmente los dos estan cerrados, se termino la conexion */
    if(*clientState == CLOSED && *serverState == CLOSED){
    
        /*El estado finish se ocupara de liberar los datos necesarios */
        return FINISH;
    }
        

    return session->sessionStateMachine.current;
}

SelectorStateDefinition flush_closy_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FLUSH_CLOSY,
        .on_arrival = flush_closy_on_arrival,
        .on_read = NULL,
        .on_write = flush_closy_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}