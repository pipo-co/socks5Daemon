#include "generateDnsQuery.h"
#include "parsers/dns/dohBuilder.h"
#include "socks5/socks5.h"

static void generate_dns_query_on_arrival(SelectorEvent *event);
static unsigned generate_dns_query_on_write(SelectorEvent *event);


static void generate_dns_query_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;
    
    if(session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.state == OPEN) {
        buffer_init(&session->socksHeader.dnsHeaderContainer.ipv4.buffer, 0, NULL);
        session->socksHeader.dnsHeaderContainer.ipv4.connected = false;
        selector_set_interest(event->s, session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd, OP_WRITE);
    }

    if(session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.state == OPEN) {
        buffer_init(&session->socksHeader.dnsHeaderContainer.ipv6.buffer, 0, NULL);
        session->socksHeader.dnsHeaderContainer.ipv6.connected = false;
        selector_set_interest(event->s, session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd, OP_WRITE);
    }

    selector_set_interest(event->s, session->clientConnection.fd, OP_NOOP);
}

static unsigned generate_dns_query_on_write(SelectorEvent *event) {
   
    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe, *dnsHeaderOther;
    uint16_t family;
    int error = 0;
    socklen_t len = sizeof(error);

    
    if(session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd == event->fd) {
        dnsHeaderMe = &session->socksHeader.dnsHeaderContainer.ipv4;
        dnsHeaderOther = &session->socksHeader.dnsHeaderContainer.ipv6;
        family = AF_INET;
    }
    else
    {
        dnsHeaderMe = &session->socksHeader.dnsHeaderContainer.ipv6;
        dnsHeaderOther = &session->socksHeader.dnsHeaderContainer.ipv4;
        family = AF_INET6;
    }
    
    if(getsockopt(dnsHeaderMe->dnsConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 || error) {
        dnsHeaderMe->dnsConnection.state == CLOSED;
        
        if(dnsHeaderOther->dnsConnection.state == CLOSED){
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        goto finally;    
    }

    if(!doh_builder_build(&dnsHeaderMe->buffer, session->clientConnection.domainName, family, socks5_get_args())) {
        dnsHeaderMe->dnsConnection.state == CLOSED;
        
        if(dnsHeaderOther->dnsConnection.state == CLOSED){
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        goto finally; 
    }

    dnsHeaderMe->connected = true;

finally:

    selector_add_interest_event(event, OP_NOOP);

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