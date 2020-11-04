#include "forwarding.h"

static unsigned forwarding_on_read(SelectorEvent *event);
static unsigned forwarding_on_write(SelectorEvent *event);
static void forwarding_on_arrival(SelectorEvent *event);
static void forwarding_calculate_new_fd_interest(SelectorEvent *event);

static void forwarding_on_arrival(SelectorEvent *event) {
    forwarding_calculate_new_fd_interest(event);
}

static unsigned forwarding_on_read(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->clientConnection.state != OPEN || session->serverConnection.state != OPEN) {
        return FLUSH_CLOSER;
    }

    forwarding_calculate_new_fd_interest(event);

    return session->sessionStateMachine.current;   
}

static unsigned forwarding_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    forwarding_calculate_new_fd_interest(event);

    return session->sessionStateMachine.current;
}

static void forwarding_calculate_new_fd_interest(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    unsigned clientInterest = OP_NOOP;
    unsigned serverInterest = OP_NOOP;

    if(buffer_can_write(&session->input)) {
        clientInterest |= OP_READ;
    }

    if(buffer_can_read(&session->input)) {
        serverInterest |= OP_WRITE;
    }

    if(buffer_can_write(&session->output)) {
        serverInterest |= OP_READ;
    }

    if(buffer_can_read(&session->output)) {
        clientInterest |= OP_WRITE;
    }

    selector_set_interest(event->s, session->clientConnection.fd, clientInterest);
    selector_set_interest(event->s, session->serverConnection.fd, serverInterest);
}

SelectorStateDefinition forwarding_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FORWARDING,
        .on_arrival = forwarding_on_arrival,
        .on_read = forwarding_on_read,
        .on_write = forwarding_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}