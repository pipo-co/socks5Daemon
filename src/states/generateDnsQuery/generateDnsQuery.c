#include "generateDnsQuery.h"
#include "parsers/dns/dohBuilder.h"

static void generate_dns_query_on_arrival(SelectorEvent *event);
static unsigned generate_dns_query_on_write(SelectorEvent *event);


static void generate_dns_query_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    buffer_init(&session->socksHeader.dnsHeader.buffer, 0, NULL);
    session->socksHeader.dnsHeader.loadedBuffer = false;
    selector_set_interest(event->s, session->clientConnection.fd, OP_NOOP);
    selector_set_interest(event->s, session->dnsConnection.fd, OP_WRITE);
}

static unsigned generate_dns_query_on_write(SelectorEvent *event) {
   
    SessionHandlerP session = (SessionHandlerP) event->data;

    if(!session->socksHeader.dnsHeader.loadedBuffer){
        int error = 0;
        socklen_t len = sizeof(error);
        if(getsockopt(session->dnsConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
            //logger stderr(errno);
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }

        if(error) {
            //logger stderr(error)???????????????
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR; 
        }
        doh_builder_build(&session->socksHeader.dnsHeader.buffer, session->clientConnection.domainName, AF_INET);
        session->socksHeader.dnsHeader.loadedBuffer = true;
    }

    if(buffer_can_read(&session->socksHeader.dnsHeader.buffer)){
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