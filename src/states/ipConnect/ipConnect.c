#include "ipConnect.h"

static unsigned ip_connect_on_post_write(SelectorEvent *event);

static unsigned ip_connect_on_post_write(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;
    int error;
    socklen_t len;

    if(getsockopt(socks5_p->serverConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1){
        selector_unregister_fd(event->s, socks5_p->serverConnection.fd);
        selector_set_interest_event(event, OP_WRITE);
        //logger stderr(errno);
        socks5_p->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }
    if(error == 0){
        selector_set_interest(event->s, socks5_p->serverConnection.fd, OP_NOOP);
        selector_set_interest_event(event, OP_WRITE);
        return REQUEST_SUCCESSFUL; 
    }
    
        //logger stderr(error)???????????????
        selector_unregister_fd(event->s, socks5_p->serverConnection.fd);
        selector_set_interest_event(event, OP_WRITE);
        socks5_p->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR; 
}

SelectorStateDefinition ip_connect_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = IP_CONNECT,
        .on_arrival = NULL,
        .on_post_read = NULL,
        .on_pre_write = NULL,
        .on_post_write = ip_connect_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
