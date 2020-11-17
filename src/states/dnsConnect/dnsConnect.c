#include "dnsConnect.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "socks5/socks5.h"
#include "netutils/netutils.h"
#include "states/stateUtilities/request/requestUtilities.h"


static void dns_connect_on_arrival(SelectorEvent *event);
static unsigned dns_connect_on_write(SelectorEvent *event);

static void dns_connect_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    selector_set_interest(event->s, session->clientConnection.fd, OP_NOOP);
    selector_set_interest(event->s, session->serverConnection.fd, OP_WRITE);
}

static unsigned dns_connect_on_write(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    int error;
    socklen_t len = sizeof(error);
    DnsHeader *ipv4 = &session->dnsHeaderContainer->ipv4;
    DnsHeader *ipv6 = &session->dnsHeaderContainer->ipv6;

    /* Se revisa si la conexion aun sigue en progreso, de no estarlo, se debe probar con otra conexion */
    if(getsockopt(session->serverConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 || error) {
        /* Ya no es valido el fd de la conexion, tengo que obtener otro */
        selector_unregister_fd(event->s, event->fd);

        if(ipv4->responseParser.addresses != NULL && ipv4->responseParser.counter < ipv4->responseParser.totalAnswers){
            /* Intentar establecer otra conexion con alguno de los ips de la lista obtenidas en la query dns */
            
            do {
                session->serverConnection.fd =
                    new_ipv4_socket(ipv4->responseParser.addresses[ipv4->responseParser.counter++].addr.ipv4,
                            session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
            
                if (session->serverConnection.fd  == -1) {
                    session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(errno); 
                }
            } while(session->serverConnection.fd  == -1 && ipv4->responseParser.counter < ipv4->responseParser.totalAnswers);
            /* si sali por la condicion de un fd distinto de -1 lo debo registrar y volver a revisar la conexion cuando
             * vuelvan a despertarme */          
            if(session->serverConnection.fd != -1) {
                socks5_register_server(session);
                return session->sessionStateMachine.current;
            }
        }

        if(ipv6->responseParser.addresses != NULL && ipv6->responseParser.counter < ipv6->responseParser.totalAnswers){
            
            do {
                session->serverConnection.fd =
                    new_ipv6_socket(ipv6->responseParser.addresses[ipv6->responseParser.counter++].addr.ipv6,
                            session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);

                if (session->serverConnection.fd  == -1) {
                    session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(errno); 
                }
            } while(session->serverConnection.fd  == -1 && ipv6->responseParser.counter < ipv6->responseParser.totalAnswers);
            /* idem caso anterior */           
            if(session->serverConnection.fd != -1) {
                socks5_register_server(session);
                return session->sessionStateMachine.current;
            }
        }
        /* si falle estableciendo otra conexion envio directamente el error que me envio el socket de mi evento */
        session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(error); 
        return REQUEST_ERROR;
    }
    
    // Para llegar a este estado se cerraron los fds y se liberaron los buffer
    // Se liberan las estructuras restantes y por ultimo todo el container.

    free(session->dnsHeaderContainer->ipv4.responseParser.addresses);
    session->dnsHeaderContainer->ipv4.responseParser.addresses = NULL;
    free(session->dnsHeaderContainer->ipv6.responseParser.addresses);
    session->dnsHeaderContainer->ipv6.responseParser.addresses = NULL;
    free(session->dnsHeaderContainer);
    session->dnsHeaderContainer = NULL;
    return REQUEST_SUCCESSFUL;
}

SelectorStateDefinition dns_connect_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = DNS_CONNECT,
        .on_arrival = dns_connect_on_arrival,
        .on_read = NULL,
        .on_write = dns_connect_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
