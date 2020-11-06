#include "request.h"
#include <errno.h>

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "buffer/buffer.h"
#include "socks5/socks5.h"
#include "parsers/request/requestParser.h"
#include "netutils/netutils.h"
#include "statistics/statistics.h"

static void request_on_arrival (SelectorEvent *event);
static unsigned request_on_read(SelectorEvent *event);
static unsigned dns_connection_handling (SelectorEvent * event);
static unsigned ip_connection_handling(SelectorEvent * event);

static void request_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    statistics_inc_current_connection();

    if(session->clientInfo.user->connectionCount == 0) {
        statistics_inc_current_user_count();
    }

    session->clientInfo.user->connectionCount++;

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
    
    if(session->socksHeader.requestHeader.parser.addressType == SOCKS_5_ADD_TYPE_DOMAIN_NAME){
        return dns_connection_handling(event);
    }
    else{
        return ip_connection_handling(event);
    }   
}

static unsigned dns_connection_handling (SelectorEvent * event){

    SessionHandlerP session = (SessionHandlerP) event->data;
    Socks5Args * args = socks5_get_args(); 
    struct in_addr ipv4addr;
    struct in6_addr ipv6addr;
    int errno4, errno6;

    if (inet_pton(AF_INET, args->doh.ip, &ipv4addr)) {
        session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.state = OPEN;
        session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd = 
            new_ipv4_socket(ipv4addr, htons(args->doh.port), (struct sockaddr *)&session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.addr);
        
        session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.state = OPEN;
        session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd =
            new_ipv4_socket(ipv4addr, htons(args->doh.port), (struct sockaddr *)&session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.addr); 

    } else if (inet_pton(AF_INET6, args->doh.ip, &ipv6addr)) {
        session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.state = OPEN;
        session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd = 
            new_ipv6_socket(ipv6addr, htons(args->doh.port), (struct sockaddr *)&session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.addr);
        errno4 = errno;

        session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.state = OPEN;
        session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd = 
            new_ipv6_socket(ipv6addr, htons(args->doh.port), (struct sockaddr *)&session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.addr);
        errno6 = errno;

    } else {
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }

    if(session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd == -1){
        session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.state = CLOSED;
    }
    
    if(session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd == -1){
        session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.state = CLOSED;
    }  
    
    if (session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd  == -1 && session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd == -1) {
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;      
    }

    session->clientConnection.domainName = malloc(DOMAIN_NAME_MAX_LENGTH);
    if(session->clientConnection.domainName == NULL){
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }
    strcpy(session->clientConnection.domainName, (char *) session->socksHeader.requestHeader.parser.address.domainName);

    socks5_register_dns(event->s, session);

    session->serverConnection.port = session->socksHeader.requestHeader.parser.port;

    return GENERATE_DNS_QUERY; 
}

static unsigned ip_connection_handling(SelectorEvent * event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.requestHeader.parser.addressType == SOCKS_5_ADD_TYPE_IP4){
        session->serverConnection.fd = 
                new_ipv4_socket(session->socksHeader.requestHeader.parser.address.ipv4,
                        session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
    }

    else if(session->socksHeader.requestHeader.parser.addressType == SOCKS_5_ADD_TYPE_IP6){
        session->serverConnection.fd = 
                new_ipv6_socket(session->socksHeader.requestHeader.parser.address.ipv6,
                        session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
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
