#include "responseDns.h"
#include <errno.h>

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "buffer/buffer.h"
#include "socks5/socks5.h"
#include "parsers/dns/dnsParser.h"
#include "netutils/netutils.h"

static void response_dns_on_arrival (SelectorEvent *event);
static unsigned response_dns_on_read(SelectorEvent *event);

static void response_dns_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    response_dns_parser_init(&session->socksHeader.dnsHeader.parser);

    selector_set_interest(event->s, session->dnsConnection.fd, OP_READ);
}

static unsigned response_dns_on_read(SelectorEvent *event) {
     
    SessionHandlerP session = (SessionHandlerP) event->data;
    bool errored;

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
        session->socksHeader.requestHeader.rep = COMMAND_NOT_SUPPORTED;
         return REQUEST_ERROR;
        //  return DNS_ERROR;
    }

    if (session->socksHeader.dnsHeader.parser.currentAnswers == 0){
        //loggear ("dnsResponse: No answers received!")
        return REQUEST_ERROR;
        // return DNS_ERROR;
    }

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
