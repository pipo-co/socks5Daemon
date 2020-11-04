#include "flushClosy.h"

static unsigned flush_closy_on_post_write(SelectorEvent *event);
static void flush_closy_on_arrival(SelectorEvent *event);



static void flush_closy_on_arrival(SelectorEvent *event) {
    flush_closy_on_post_write(event);
}

static unsigned flush_closy_on_post_write(SelectorEvent *event) {
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    int clientFd = socks5_p->clientConnection.fd;
    int serverFd = socks5_p->serverConnection.fd;

    SocketState *clientState = &socks5_p->clientConnection.state;
    SocketState *serverState = &socks5_p->serverConnection.state;

    Buffer clientBuffer = socks5_p->input;
    Buffer serverBuffer = socks5_p->output;

    if(buffer_can_read(&clientBuffer)) {
        selector_set_interest(event->s, serverFd, OP_WRITE);
    }
    else if(*clientState == CLOSING) {
        shutdown(serverFd, SHUT_WR);
        *clientState = CLOSED;
    }

    if(buffer_can_read(&serverBuffer)) {
        selector_set_interest(event->s, clientFd, OP_WRITE);
    }
    else if(*serverState == CLOSING) {
        shutdown(clientFd, SHUT_WR);
        *serverState = CLOSED;
    }

    if(*clientState == CLOSED && *serverState == CLOSED)
        return FINISH;

    return socks5_p->sessionStateMachine.current;
}



SelectorStateDefinition flush_closy_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FLUSH_CLOSY,
        .on_arrival = flush_closy_on_arrival,
        .on_post_read = NULL,
        .on_pre_write = NULL,
        .on_post_write = flush_closy_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}