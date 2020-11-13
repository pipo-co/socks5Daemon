
#include "flushCloser.h"

static unsigned flush_closer_on_read(SelectorEvent *event);
static unsigned flush_closer_on_write(SelectorEvent *event);
static void flush_closer_on_arrival(SelectorEvent *event);

static void flush_closer_on_arrival(SelectorEvent *event) {
    flush_closer_on_write(event);
}

static unsigned flush_closer_on_read(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    Buffer closyBuffer;
    int closerFd;
    unsigned *closyState, *closerState;

    // Client = Closy
    // Server = Closer
    if(session->clientConnection.fd == event->fd) {

        closerFd = session->serverConnection.fd;
        closyBuffer = session->input;

        closyState = &session->clientConnection.state;
        closerState = &session->serverConnection.state;
    }

    // Server = Closy
    // Client = Closer
    else {

        closerFd = session->clientConnection.fd;
        closyBuffer = session->output;

        closyState = &session->serverConnection.state;
        closerState = &session->clientConnection.state;
    }

    // Transicion de estados 
    if(*closyState == CLOSING) {

        /* Si ninguno de los dos buffer necesita ser vaciado, ya terminamos */
        if(*closerState == CLOSED && !buffer_can_read(&closyBuffer)) {
            /*Se le realiza el shutdown al fd indicando que no se escribira mas por ahi */
            shutdown(closerFd, SHUT_WR);
            *closyState = CLOSED;
            /* El estado finish se ocupara de liberar los datos necesarios */
            return FINISH;
        }

        return FLUSH_CLOSY;
    }

    if(buffer_can_write(&closyBuffer)) {
        selector_add_interest_event(event, OP_READ);
    }

    if(buffer_can_read(&closyBuffer)) {
        selector_set_interest(event->s, closerFd, OP_WRITE);
    }

    return session->sessionStateMachine.current;
}

static unsigned flush_closer_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    Buffer closyBuffer, closerBuffer;

    int closyFd, closerFd;

    SocketState *closerStateP;

    // Client = Closy
    // Server = Closer
    if(session->clientConnection.state == OPEN) {

        closyFd = session->clientConnection.fd;
        closerFd = session->serverConnection.fd;

        closyBuffer = session->input;
        closerBuffer = session->output;

        closerStateP = &session->serverConnection.state;
    }

    // Server = Closy
    // Client = Closer
    else {

        closyFd = session->serverConnection.fd;
        closerFd = session->clientConnection.fd;

        closyBuffer = session->output;
        closerBuffer = session->input;

        closerStateP = &session->clientConnection.state;
    }

    int closyInterest = OP_NOOP;
    int closerInterest = OP_NOOP;

    if(buffer_can_write(&closyBuffer)) {
        closyInterest |= OP_READ;
    }

    if(buffer_can_read(&closyBuffer)) {
        closerInterest |= OP_WRITE;
    }

    /* Si todavia hay cosas que vaciar de closer */
    if(buffer_can_read(&closerBuffer)) {
        closyInterest |= OP_WRITE;
    }

    /* Si ya no hay nada que mandarle al closer pero todavía no le mandamos el shutdown */
    else if(*closerStateP == CLOSING) {
        shutdown(closyFd, SHUT_WR);
        *closerStateP = CLOSED;
    }

    selector_set_interest(event->s, closyFd, closyInterest);
    selector_set_interest(event->s, closerFd, closerInterest);

    return session->sessionStateMachine.current;
}


SelectorStateDefinition flush_closer_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FLUSH_CLOSER,
        .on_arrival = flush_closer_on_arrival,
        .on_read = flush_closer_on_read,
        .on_write = flush_closer_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
