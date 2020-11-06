#include "generateDnsQuery.h"
#include "parsers/dns/dohBuilder.h"
#include "socks5/socks5.h"

static void generate_dns_query_on_arrival(SelectorEvent *event);
static unsigned generate_dns_query_on_write(SelectorEvent *event);

static void generate_dns_query_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;
    
    if(session->dnsHeaderContainer->ipv4.dnsConnection.state == OPEN) {
        buffer_init(&session->dnsHeaderContainer->ipv4.buffer, 0, NULL);
        session->dnsHeaderContainer->ipv4.connected = false;
        selector_set_interest(event->s, session->dnsHeaderContainer->ipv4.dnsConnection.fd, OP_WRITE);
    }

    if(session->dnsHeaderContainer->ipv6.dnsConnection.state == OPEN) {
        buffer_init(&session->dnsHeaderContainer->ipv6.buffer, 0, NULL);
        session->dnsHeaderContainer->ipv6.connected = false;
        selector_set_interest(event->s, session->dnsHeaderContainer->ipv6.dnsConnection.fd, OP_WRITE);
    }

    selector_set_interest(event->s, session->clientConnection.fd, OP_NOOP);
}

static unsigned generate_dns_query_on_write(SelectorEvent *event) {
   
    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe, *dnsHeaderOther;
    uint16_t family;
    int error = 0;
    socklen_t len = sizeof(error);

    if(session->dnsHeaderContainer->ipv4.dnsConnection.fd == event->fd) {
        dnsHeaderMe = &session->dnsHeaderContainer->ipv4;
        dnsHeaderOther = &session->dnsHeaderContainer->ipv6;
        family = AF_INET;
    }
    else {
        dnsHeaderMe = &session->dnsHeaderContainer->ipv6;
        dnsHeaderOther = &session->dnsHeaderContainer->ipv4;
        family = AF_INET6;
    }
    
    if(getsockopt(dnsHeaderMe->dnsConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 || error) {
        
        // Cerramos el Fd de la conexion que salio mal
        dnsHeaderMe->dnsConnection.state == INVALID;
        selector_unregister_fd(event->s, event->fd);

        if(dnsHeaderOther->dnsConnection.state == INVALID){
            free(session->dnsHeaderContainer);
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        goto finally;    
    }

    if(!doh_builder_build(&dnsHeaderMe->buffer, session->socksHeader.requestHeader.parser.address.domainName, family, socks5_get_args())) {
        
        free(dnsHeaderMe->buffer.data);
        dnsHeaderMe->buffer.data = NULL;

        // Cerramos el Fd
        dnsHeaderMe->dnsConnection.state == INVALID;
        selector_unregister_fd(event->s, event->fd);
        
        if(dnsHeaderOther->dnsConnection.state == INVALID){
            free(session->dnsHeaderContainer);
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        goto finally; 
    }

    dnsHeaderMe->connected = true;
    selector_add_interest_event(event, OP_NOOP);

finally:

    if(dnsHeaderOther->dnsConnection.state == OPEN && !dnsHeaderOther->connected){
        return session->sessionStateMachine.current;
    }

    return RESPONSE_DNS;
}

SelectorStateDefinition generate_dns_query_state_definition_supplier(void){
    
    SelectorStateDefinition stateDefinition = {

        .state = GENERATE_DNS_QUERY,
        .on_arrival = generate_dns_query_on_arrival,
        .on_read = NULL,
        .on_write = generate_dns_query_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };
    return stateDefinition;
}