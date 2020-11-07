#include "responseDns.h"
#include <errno.h>

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "buffer/buffer.h"
#include "socks5/socks5.h"
#include "parsers/dns/httpDnsParser.h"
#include "parsers/dns/dnsParser.h"
#include "netutils/netutils.h"

static void response_dns_on_arrival (SelectorEvent *event);
static unsigned response_dns_on_read(SelectorEvent *event);
static unsigned response_dns_on_write(SelectorEvent *event);

static void response_dns_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->dnsHeaderContainer->ipv4.dnsConnection.state == OPEN) {

        session->dnsHeaderContainer->ipv4.connected = false;
        http_dns_parser_init(&session->dnsHeaderContainer->ipv4.httpParser);
        response_dns_parser_init(&session->dnsHeaderContainer->ipv4.responseParser);
        selector_set_interest(event->s, session->dnsHeaderContainer->ipv4.dnsConnection.fd, OP_WRITE);
    }

    if(session->dnsHeaderContainer->ipv6.dnsConnection.state == OPEN) {
        
        session->dnsHeaderContainer->ipv6.connected = false;
        http_dns_parser_init(&session->dnsHeaderContainer->ipv6.httpParser);
        response_dns_parser_init(&session->dnsHeaderContainer->ipv6.responseParser);
        selector_set_interest(event->s, session->dnsHeaderContainer->ipv6.dnsConnection.fd, OP_WRITE);
    }
}

// Cuando ya se sabe que se termina en request error no se limpia nada extra 
// y se deja que limpie el estado finish. Especialmente la estructura DnsHeaderContainer

static unsigned response_dns_on_read(SelectorEvent *event) {
     
    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe, *dnsHeaderOther;
    bool errored;

    if(session->dnsHeaderContainer->ipv4.dnsConnection.fd == event->fd) {
        dnsHeaderMe = &session->dnsHeaderContainer->ipv4;
        dnsHeaderOther = &session->dnsHeaderContainer->ipv6;
    }
    else {
        dnsHeaderMe = &session->dnsHeaderContainer->ipv6;
        dnsHeaderOther = &session->dnsHeaderContainer->ipv4;
    }

    if(dnsHeaderMe->dnsConnection.state == INVALID) {

        if(dnsHeaderOther->dnsConnection.state == INVALID) {
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        
        goto finally;
    }

    if(!http_dns_parser_consume(&dnsHeaderMe->buffer, &dnsHeaderMe->httpParser, &errored)){
        return session->sessionStateMachine.current;
    } 
    else if(!errored && !response_dns_parser_consume(&dnsHeaderMe->buffer, &dnsHeaderMe->responseParser, &errored)){
        return session->sessionStateMachine.current;
    } 
    else if(!errored && (dnsHeaderMe->responseParser.totalQuestions == 0 || dnsHeaderMe->responseParser.totalAnswers == 0)){   
        errored = true;
    } 
    else if(!errored && dnsHeaderMe->responseParser.currentType != SOCKS_5_ADD_TYPE_IP4 && dnsHeaderMe->responseParser.currentType != SOCKS_5_ADD_TYPE_IP6){
        errored = true;
    }

    if (errored){

        dnsHeaderMe->dnsConnection.state = INVALID;
        selector_unregister_fd(event->s, event->fd);
        free(dnsHeaderMe->buffer.data);
        free(dnsHeaderMe->responseParser.addresses);
        dnsHeaderMe->buffer.data = NULL;
        dnsHeaderMe->responseParser.addresses = NULL;

        if(dnsHeaderOther->dnsConnection.state == INVALID) {
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }

        goto finally;
    }

    // response_dns_parser_is_done
    // Terminaste parsing -> Tengo la lista con las IPs posibles

    if(dnsHeaderOther->dnsConnection.state == OPEN && dnsHeaderOther->connected){
        // Tengo todas las IPs == Haber llegado hasta aca
        // Tengo una IP que paso el primer connect. == Estar connected
        return DNS_CONNECT;
    }

    do{
        if(dnsHeaderMe->responseParser.currentType == SOCKS_5_ADD_TYPE_IP4){
            session->serverConnection.fd =
                    new_ipv4_socket(dnsHeaderMe->responseParser.addresses[dnsHeaderMe->responseParser.counter++].addr.ipv4,
                            session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
        }
        else {
            session->serverConnection.fd =
                    new_ipv6_socket(dnsHeaderMe->responseParser.addresses[dnsHeaderMe->responseParser.counter++].addr.ipv6,
                            session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
        }

        if (session->serverConnection.fd  == -1) {

            if(errno == ENETUNREACH){
                session->socksHeader.requestHeader.rep = NETWORK_UNREACHABLE;
            }

            else if(errno = EHOSTUNREACH) {
                session->socksHeader.requestHeader.rep = HOST_UNREACHABLE;
            }

            else if(errno = ECONNREFUSED) {
                session->socksHeader.requestHeader.rep = CONNECTION_REFUSED;
            }

            else {
                session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            } 
        }
    } while(session->serverConnection.fd  == -1 && dnsHeaderMe->responseParser.counter < dnsHeaderMe->responseParser.totalAnswers);

    // Saliste con -1 -> se quedo sin addr para probar 
    // Saliste con != -1 -> hay conexion. (puede o no haber mas en la lista) 

    if(session->serverConnection.fd  == -1) {

        dnsHeaderMe->dnsConnection.state = INVALID;
        selector_unregister_fd(event->s, event->fd);
        free(dnsHeaderMe->buffer.data);
        free(dnsHeaderMe->responseParser.addresses);
        dnsHeaderMe->buffer.data = NULL;
        dnsHeaderMe->responseParser.addresses = NULL;

        if(dnsHeaderOther->dnsConnection.state == INVALID){
            // Mensaje de error viene de adentro del while. Error del ultimo intento de conexion. Hay que elegir uno.
            return REQUEST_ERROR;
        }
        goto finally;
    }

    socks5_register_server(event->s, session);
    dnsHeaderMe->connected = true;
    selector_set_interest_event(event, OP_NOOP);

    // Si se llega desde el goto -> Ya sabemos que el otro esta open pero 
    // no sabemos si ya habia terminado o no

    // Todo lo que llega al finally ya no se despierta mas. Esta unregistered o con interest en OP_NOOP
finally:   
    if(dnsHeaderOther->dnsConnection.state == OPEN && !response_dns_parser_is_done(dnsHeaderOther->responseParser.currentState, &errored)){
        
        return session->sessionStateMachine.current;
    }

    // TODO No deberia hacer falta ahora
    // session->clientInfo.addressTypeSelected = session->socksHeader.requestHeader.parser.addressType;

    return DNS_CONNECT;
}

static unsigned response_dns_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe, *dnsHeaderOther;

    if(session->dnsHeaderContainer->ipv4.dnsConnection.fd == event->fd) {
        dnsHeaderMe = &session->dnsHeaderContainer->ipv4;
        dnsHeaderOther = &session->dnsHeaderContainer->ipv4;
    }
    else {
        dnsHeaderMe = &session->dnsHeaderContainer->ipv6;
        dnsHeaderOther = &session->dnsHeaderContainer->ipv6;
    }

    if(dnsHeaderMe->dnsConnection.state == INVALID) {

        if(dnsHeaderOther->dnsConnection.state == INVALID) {
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        goto finally;
    }

    if(!buffer_can_read(&dnsHeaderMe->buffer)){
        selector_set_interest_event(event, OP_READ);
    }

finally:
    return session->sessionStateMachine.current;
}

SelectorStateDefinition response_dns_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = RESPONSE_DNS,
        .on_arrival = response_dns_on_arrival,
        .on_read = response_dns_on_read,
        .on_write = response_dns_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
