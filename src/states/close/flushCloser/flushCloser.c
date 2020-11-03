
#include "flushCloser.h"

static unsigned flush_closer_on_post_read(SelectorEvent *event);
static unsigned flush_closer_on_post_write(SelectorEvent *event);
static void flush_closer_on_arrival(SelectorEvent *event);

static void flush_closer_on_arrival(SelectorEvent *event) {
    flush_closer_on_post_write(event);
}

static unsigned flush_closer_on_post_read(SelectorEvent *event) {
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    Buffer closyBuffer;

    int closerFd;

    // Client = Closy
    // Server = Closer
    if(socks5_p->clientConnection.fd == event->fd) {
        if(socks5_p->clientConnection.state == CLOSING)
            return FLUSH_CLOSY;

        closerFd = socks5_p->serverConnection.fd;
        closyBuffer = socks5_p->input;
    }

    // Server = Closy
    // Client = Closer
    else {
        if(socks5_p->serverConnection.state == CLOSING)
            return FLUSH_CLOSY;

        closerFd = socks5_p->clientConnection.fd;
        closyBuffer = socks5_p->output;
    }

    if(buffer_can_write(&closyBuffer)) {
        selector_set_interest_event(event, OP_READ + lo que habia antes);
    }

    if(buffer_can_read(&closyBuffer)) {
        selector_set_interest(event->s, closerFd, OP_WRITE);
    }

    return FLUSH_CLOSER;
}

static unsigned flush_closer_on_post_write(SelectorEvent *event) {
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    Buffer closyBuffer, closerBuffer;

    int closyFd, closerFd;

    SocketState *closerStateP;

    // Client = Closy
    // Server = Closer
    if(socks5_p->clientConnection.state == OPEN) {

        closyFd = socks5_p->clientConnection.fd;
        closerFd = socks5_p->serverConnection.fd;

        closyBuffer = socks5_p->input;
        closerBuffer = socks5_p->output;

        closerStateP = &socks5_p->serverConnection.state;
    }

    // Server = Closy
    // Client = Closer
    else {

        closyFd = socks5_p->serverConnection.fd;
        closerFd = socks5_p->clientConnection.fd;

        closyBuffer = socks5_p->output;
        closerBuffer = socks5_p->input;

        closerStateP = &socks5_p->clientConnection.state;
    }

    int closyInterest = OP_NOOP;
    int closerInterest = OP_NOOP;

    if(buffer_can_write(&closyBuffer)) {
        closyInterest |= OP_READ;
    }

    if(buffer_can_read(&closyBuffer)) {
        closerInterest |= OP_WRITE;
    }

    // Si todavia hay cosas que flushear de closer
    if(buffer_can_read(&closerBuffer)) {
        closyInterest |= OP_WRITE;
    }

    // Si ya no hay nada que mandarle al closer pero todavía no le mandamos el shutdown
    else if(*closerStateP == CLOSING) {
        shutdown(closerFd, SHUT_RD);
        *closerStateP = CLOSED;
    }

    selector_set_interest(event->s, closyFd, closyInterest);
    selector_set_interest(event->s, closerFd, closerInterest);

    return FLUSH_CLOSER;
}


SelectorStateDefinition flush_closer_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FLUSH_CLOSER,
        .on_arrival = flush_closer_on_arrival,
        .on_post_read = flush_closer_on_post_read,
        .on_pre_write = NULL,
        .on_post_write = flush_closer_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}