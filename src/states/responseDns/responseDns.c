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

    http_dns_parser_init(&session->socksHeader.dnsHeader.httpParser);
    response_dns_parser_init(&session->socksHeader.dnsHeader.parser);

    selector_set_interest(event->s, session->dnsConnection.fd, OP_READ);
}

static unsigned response_dns_on_read(SelectorEvent *event) {
     
    SessionHandlerP session = (SessionHandlerP) event->data;
    bool errored;

    if(!http_dns_parser_consume(&session->socksHeader.dnsHeader.buffer, &session->socksHeader.dnsHeader.httpParser, &errored)){
        return session->sessionStateMachine.current;
    }

    if (errored == true){
        //loggear ( response_dns_parser_error_message();)
        return REQUEST_ERROR;
        // return DNS_ERROR;
    }

    if(!response_dns_parser_consume(&session->socksHeader.dnsHeader.buffer, &session->socksHeader.dnsHeader.parser, &errored)){
        return session->sessionStateMachine.current;
    }
    if (errored == true){
        //loggear ( response_dns_parser_error_message();)
        return REQUEST_ERROR;
        // return DNS_ERROR;
    }

    if (session->socksHeader.dnsHeader.parser.totalQuestions == 0){
        //loggear ("dnsResponse: No questions received!")
        
        return REQUEST_ERROR;
        //  return DNS_ERROR;
    }

    if (session->socksHeader.dnsHeader.parser.currentAnswers == 0){
        //loggear ("dnsResponse: No answers received!")
        return REQUEST_ERROR;
        // return DNS_ERROR;
    }

    if(session->socksHeader.dnsHeader.parser.currentType == SOCKS_5_ADD_TYPE_IP4){
        session->serverConnection.fd =
                new_ipv4_socket(session->socksHeader.dnsHeader.parser.addresses[session->socksHeader.dnsHeader.parser.addressRemaining].addr.ipv4,
                        session->serverConnection.port, (struct sockaddr *)&session->serverConnection.addr);
    }

    else if(session->socksHeader.dnsHeader.parser.currentType == SOCKS_5_ADD_TYPE_IP6){
        session->serverConnection.fd =
                new_ipv6_socket(session->socksHeader.dnsHeader.parser.addresses[session->socksHeader.dnsHeader.parser.addressRemaining].addr.ipv6,
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
    selector_set_interest(event->s, session->dnsConnection.fd, OP_NOOP);
    socks5_register_server(event->s, session);

    return IP_CONNECT;
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
