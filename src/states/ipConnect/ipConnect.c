#include "ipConnect.h"

static void ip_connect_on_arrival(SelectorEvent *event);
static unsigned ip_connect_on_write(SelectorEvent *event);

static void ip_connect_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    selector_set_interest(event->s, session->clientConnection.fd, OP_NOOP);
    selector_set_interest(event->s, session->serverConnection.fd, OP_WRITE);
}

static unsigned ip_connect_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    int error;
    socklen_t len = sizeof(error);

    if(getsockopt(session->serverConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 || error) {
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }

    return REQUEST_SUCCESSFUL;
}

SelectorStateDefinition ip_connect_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = IP_CONNECT,
        .on_arrival = ip_connect_on_arrival,
        .on_read = NULL,
        .on_write = ip_connect_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
