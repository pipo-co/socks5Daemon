#include "generateDnsQuery.h"
#include "parsers/dns/dohBuilder.h"
#include "socks5/socks5.h"
#include "states/stateUtilities/request/requestUtilities.h"

static void generate_dns_query_on_arrival(SelectorEvent *event);
static unsigned generate_dns_query_on_write(SelectorEvent *event);


static void generate_dns_query_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    /* solo debo ocuparme de inicializar lo pertinente a aquellos connect que no fallaron en el estado anterior */
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
    /* En caso de no estar ya en un estado invalido, se revisan las opciones del socket para comprobar si efectivamente se pudo establecer la conexion */
    if(dnsHeaderMe->dnsConnection.state == INVALID || getsockopt(dnsHeaderMe->dnsConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 || error) {
        
        if(dnsHeaderOther->dnsConnection.state == INVALID){
            if(error != 0){
                session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(error);
            }
            else {
                session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            }
            return REQUEST_ERROR;
        }

        // Liberar todo lo mio porque soy invalid y el otro no
        if(dnsHeaderMe->dnsConnection.state != INVALID){
            selector_unregister_fd(event->s, event->fd);
        }

        free(dnsHeaderMe->buffer.data);
        dnsHeaderMe->buffer.data = NULL;
        return session->sessionStateMachine.current;  
    }

    /* Cargar en mi buffer de salida la query dns*/
    if(doh_builder_build(&dnsHeaderMe->buffer, (char *)session->socksHeader.requestHeader.parser.address.domainName, family, socks5_get_args()) != 0) {
        
        if(dnsHeaderOther->dnsConnection.state == INVALID){
            if(error != 0){
                session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(error);
            }
            else {
                session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            }
            return REQUEST_ERROR;
        }
        
        // Liberar todo lo mio porque soy invalid y el otro no
        selector_unregister_fd(event->s, event->fd);
        free(dnsHeaderMe->buffer.data);
        dnsHeaderMe->buffer.data = NULL;
        return session->sessionStateMachine.current; 
    }

    dnsHeaderMe->connected = true;
    // A mi no me tienen que despertar mas, ahora que termine el otro pedido, que todavia no esta conectado
    if(dnsHeaderOther->dnsConnection.state == OPEN && !dnsHeaderOther->connected){
        selector_set_interest_event(event, OP_NOOP);
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