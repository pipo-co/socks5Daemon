#include "request.h"

#include <stdlib.h> //malloc
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h> 
#include <arpa/inet.h>

#include "buffer/buffer.h"
#include "socks5/socks5.h"
#include "parsers/request/requestParser.h"
#include "netutils/netutils.h"
#include "statistics/statistics.h"
#include "states/stateUtilities/request/requestUtilities.h"

static void request_on_arrival (SelectorEvent *event);
static unsigned request_on_read(SelectorEvent *event);
static unsigned dns_connection_handling (SelectorEvent * event);
static unsigned ip_connection_handling(SelectorEvent * event);

static void request_on_arrival (SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

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
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }

    if (session->socksHeader.requestHeader.parser.version != SOCKS_VERSION){
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }
    
    if (session->socksHeader.requestHeader.parser.cmd != REQUEST_PARSER_COMMAND_CONNECT){
        session->socksHeader.requestHeader.rep = COMMAND_NOT_SUPPORTED;
        return REQUEST_ERROR;
    }

    session->clientInfo.port = session->socksHeader.requestHeader.parser.port;
    
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

    session->clientInfo.addressTypeSelected = SOCKS_5_ADD_TYPE_DOMAIN_NAME;
    session->clientInfo.connectedDomain = malloc(DOMAIN_NAME_MAX_LENGTH);
    if(session->clientInfo.connectedDomain == NULL){
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }
    strncpy(session->clientInfo.connectedDomain, (char *) session->socksHeader.requestHeader.parser.address.domainName, UINT8_STR_MAX_LENGTH);


    // Verificar la IP del servidor DoH. (IPv4 o IPv6)
    if (inet_pton(AF_INET, args->doh.ip, &ipv4addr)) {
        
        session->dnsHeaderContainer = calloc(1, sizeof(*session->dnsHeaderContainer));
        if(session->dnsHeaderContainer == NULL){
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        /* para todas las conexiones, en primer instancia se debera realizar un connect trial. Si el connect devuelve en errno el valor
         * EINPROGRES se registra el socket para de esta manera, cuando nos vuelvan a llamar en un estado proximo, revisar las 
         * opciones del socket para ver si no ha habido error al establecer la conexion */

        // Conexion para solicitud A
        session->dnsHeaderContainer->ipv4.dnsConnection.state = OPEN;
        session->dnsHeaderContainer->ipv4.dnsConnection.fd = 
            new_ipv4_socket(ipv4addr, htons(args->doh.port), (struct sockaddr *)&session->dnsHeaderContainer->ipv4.dnsConnection.addr);
        
        // Conexion para solicitud AAAA
        session->dnsHeaderContainer->ipv6.dnsConnection.state = OPEN;
        session->dnsHeaderContainer->ipv6.dnsConnection.fd =
            new_ipv4_socket(ipv4addr, htons(args->doh.port), (struct sockaddr *)&session->dnsHeaderContainer->ipv6.dnsConnection.addr); 
    } 
    else if (inet_pton(AF_INET6, args->doh.ip, &ipv6addr)) {
        
        session->dnsHeaderContainer = calloc(1, sizeof(*session->dnsHeaderContainer));
        if(session->dnsHeaderContainer == NULL){
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        }
        
        // Conexion para solicitud A
        session->dnsHeaderContainer->ipv4.dnsConnection.state = OPEN;
        session->dnsHeaderContainer->ipv4.dnsConnection.fd = 
            new_ipv6_socket(ipv6addr, htons(args->doh.port), (struct sockaddr *)&session->dnsHeaderContainer->ipv4.dnsConnection.addr);

        // Conexion para solicitud AAAA
        session->dnsHeaderContainer->ipv6.dnsConnection.state = OPEN;
        session->dnsHeaderContainer->ipv6.dnsConnection.fd = 
            new_ipv6_socket(ipv6addr, htons(args->doh.port), (struct sockaddr *)&session->dnsHeaderContainer->ipv6.dnsConnection.addr);
    } 
    else {
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }

    // Fd con error distinto a EINPROGRES
    if(session->dnsHeaderContainer->ipv4.dnsConnection.fd == -1){
        session->dnsHeaderContainer->ipv4.dnsConnection.state = INVALID;
    }
    
    if(session->dnsHeaderContainer->ipv6.dnsConnection.fd == -1){
        session->dnsHeaderContainer->ipv6.dnsConnection.state = INVALID;
    }  
    /* Si no se logro establecer el primer intento de conexion ni para pedidos de ipv4 ni de ipv6 entonces no se podra establecer la conexion
     * con el servidor destino del pedido, por lo que habra un error. Si al menos una de las dos conexiones se logro, se debera
     * intentar terminar de establecer la conexion y realizar el pedido dns*/
    if (session->dnsHeaderContainer->ipv4.dnsConnection.state == INVALID && session->dnsHeaderContainer->ipv6.dnsConnection.state == INVALID) {
        
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;      
    }

    socks5_register_dns(session);

    /* tendre que realizar un pedido al servidor doh para conseguir la ip del dominio enviado por el cliente */
    return GENERATE_DNS_QUERY; 
}

static unsigned ip_connection_handling(SelectorEvent * event){
    SessionHandlerP session = (SessionHandlerP) event->data;
    session->clientInfo.addressTypeSelected = session->socksHeader.requestHeader.parser.addressType;

    /* para todas las conexiones, en primer instancia se debera realizar un connect trial. Si el connect devuelve en errno el valor
     * EINPROGRES se registra el socket para de esta manera, cuando nos vuelvan a llamar en un estado proximo, revisar las 
     * opciones del socket para ver si no ha habido error al establecer la conexion */

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

        session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(errno);
        return REQUEST_ERROR;      
    }

    socks5_register_server(session);

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
