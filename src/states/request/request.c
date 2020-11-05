#include "request.h"
#include <errno.h>

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "buffer/buffer.h"
#include "socks5/socks5.h"
#include "parsers/request/requestParser.h"
#include "netutils/netutils.h"

static void request_on_arrival (SelectorEvent *event);
static unsigned request_on_read(SelectorEvent *event);

static void request_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    request_parser_init(&session->socksHeader.requestHeader.parser);

    session->socksHeader.requestHeader.rep = SUCCESSFUL;

    selector_set_interest(event->s, session->clientConnection.fd, OP_READ);
}

static unsigned request_on_read(SelectorEvent *event) {
     
    SessionHandlerP session = (SessionHandlerP) event->data;
    bool errored;

    if(!request_parser_consume(&session->input, &session->socksHeader.requestHeader.parser, &errored)){
        return session->sessionStateMachine.current;
    }
    if (errored == true){
        //loggear ( request_parser_error_message(socks5_p->request_parser.current_state);)
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }

    if (session->socksHeader.requestHeader.parser.version != SOCKS_VERSION){
        //loggear ("Request: Invalid version!")
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }
    
    if (session->socksHeader.requestHeader.parser.cmd != REQUEST_PARSER_COMMAND_CONNECT){
        //loggear ("Request: Unsupported command!")
        session->socksHeader.requestHeader.rep = COMMAND_NOT_SUPPORTED;
        return REQUEST_ERROR;
    }
    
    if(session->socksHeader.requestHeader.parser.addressType == REQUEST_PARSER_ADD_TYPE_DOMAIN_NAME){
        // connectDoh(socks5_p)
        //registrar al selector el fd del dns
        return FINISH; // TODO: GENERATE_DNS_QUERY; 
    }
    
    if(session->socksHeader.requestHeader.parser.addressType == REQUEST_PARSER_ADD_TYPE_IP4){
        session->serverConnection.fd = 
                new_ipv4_socket(session->socksHeader.requestHeader.parser.address.ipv4,
                        session->socksHeader.requestHeader.parser.port, &session->serverConnection.addr);
    }

    else if(session->socksHeader.requestHeader.parser.addressType == REQUEST_PARSER_ADD_TYPE_IP6){
        session->serverConnection.fd = 
                new_ipv6_socket(session->socksHeader.requestHeader.parser.address.ipv6,
                        session->socksHeader.requestHeader.parser.port, &session->serverConnection.addr);
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

    socks5_register_server(event->s, session);

    return IP_CONNECT;
}

SelectorStateDefinition request_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST,
        .on_arrival = request_on_arrival,
        .on_read = request_on_read,
        .on_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
