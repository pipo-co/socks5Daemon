#include "dnsConnect.h"

static void dns_connect_on_arrival(SelectorEvent *event);
static unsigned dns_connect_on_write(SelectorEvent *event);

static void dns_connect_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    selector_set_interest(event->s, session->clientConnection.fd, OP_NOOP);
    selector_set_interest(event->s, session->dnsConnection.fd, OP_NOOP);
    selector_set_interest(event->s, session->serverConnection.fd, OP_WRITE);
}

static unsigned dns_connect_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    int error;
    socklen_t len = sizeof(error);

    if(getsockopt(session->serverConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        //logger stderr(errno);
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
        
    }

    if(error) {
        if(session->socksHeader.dnsHeader.parser.counter < session->socksHeader.dnsHeader.parser.totalAnswers){
            session->socksHeader.dnsHeader.parser.counter++;
            
            socks5_unregister_server(event->s, session);

            if(session->socksHeader.dnsHeader.parser.currentType == SOCKS_5_ADD_TYPE_IP4){
                session->serverConnection.fd =
                    new_ipv4_socket(session->socksHeader.dnsHeader.parser.addresses[session->socksHeader.dnsHeader.parser.counter].addr.ipv4,
                            session->serverConnection.port, (struct sockaddr *)&session->serverConnection.addr);
            }

            else if(session->socksHeader.dnsHeader.parser.currentType == SOCKS_5_ADD_TYPE_IP6){
                session->serverConnection.fd =
                        new_ipv6_socket(session->socksHeader.dnsHeader.parser.addresses[session->socksHeader.dnsHeader.parser.counter].addr.ipv6,
                                session->serverConnection.port, (struct sockaddr *)&session->serverConnection.addr);
            }
        

            socks5_register_server(event->s, session);
            selector_set_interest(event->s, session->serverConnection.fd, OP_WRITE);
            
            return DNS_CONNECT;
        }
        else
        {
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        } 
    }

    return REQUEST_SUCCESSFUL;
}
 
 