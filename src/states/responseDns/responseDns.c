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

static void response_dns_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.state == OPEN) {
        
        http_dns_parser_init(&session->socksHeader.dnsHeaderContainer.ipv4.httpParser);
        response_dns_parser_init(&session->socksHeader.dnsHeaderContainer.ipv4.responseParser);
        selector_set_interest(event->s, session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd, OP_WRITE);
    }

    if(session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.state == OPEN) {
        http_dns_parser_init(&session->socksHeader.dnsHeaderContainer.ipv6.httpParser);
        response_dns_parser_init(&session->socksHeader.dnsHeaderContainer.ipv6.responseParser);
        selector_set_interest(event->s, session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd, OP_WRITE);
    }
}

static unsigned response_dns_on_read(SelectorEvent *event) {
     
    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe, *dnsHeaderOther;
    bool errored;

    if(session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd == event->fd) {
        dnsHeaderMe = &session->socksHeader.dnsHeaderContainer.ipv4;
        dnsHeaderOther = &session->socksHeader.dnsHeaderContainer.ipv6;
    }
    else {
        dnsHeaderMe = &session->socksHeader.dnsHeaderContainer.ipv6;
        dnsHeaderOther = &session->socksHeader.dnsHeaderContainer.ipv4;
    }

    if(!http_dns_parser_consume(&dnsHeaderMe->buffer, &dnsHeaderMe->httpParser, &errored)){
        return session->sessionStateMachine.current;
    }

    if (errored == true){
        
        if(dnsHeaderOther->dnsConnection.state == OPEN){
            if(response_dns_parser_is_done(dnsHeaderOther->responseParser.currentState, &errored)){
                return DNS_CONNECT;
            }
        }
        else{
            return REQUEST_ERROR;
        }
    }

    if(!response_dns_parser_consume(&dnsHeaderMe->buffer, &dnsHeaderMe->responseParser, &errored)){
        return session->sessionStateMachine.current;
    }
    if (errored == true){
        return REQUEST_ERROR;
        // return DNS_ERROR;
    }

    if (dnsHeaderMe->responseParser.totalQuestions == 0){
        
        return REQUEST_ERROR;
        //  return DNS_ERROR;
    }

    if (dnsHeaderMe->responseParser.totalAnswers == 0){

        return REQUEST_ERROR;
        // return DNS_ERROR;
    }

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

    else {
        session->socksHeader.requestHeader.rep = ADDRESS_TYPE_NOT_SUPPORTED;
        return REQUEST_ERROR;
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

        //logger stderr(errno);
        return REQUEST_ERROR;      
    }

    session->clientInfo.addressTypeSelected = session->socksHeader.requestHeader.parser.addressType;
    socks5_register_server(event->s, session);

    return DNS_CONNECT;
}

static unsigned response_dns_on_write(SelectorEvent *event){

    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe;

    if(session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd == event->fd) {
        dnsHeaderMe = &session->socksHeader.dnsHeaderContainer.ipv4;
    }
    else
    {
        dnsHeaderMe = &session->socksHeader.dnsHeaderContainer.ipv6;
    }

    if(!buffer_can_read(&dnsHeaderMe->buffer)){
        selector_set_interest_event(event, OP_READ);
    }

    return session->sessionStateMachine.current;
}

SelectorStateDefinition response_dns_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = RESPONSE_DNS,
        .on_arrival = response_dns_on_arrival,
        .on_read = response_dns_on_read,
        .on_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
