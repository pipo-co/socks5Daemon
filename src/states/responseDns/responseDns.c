#include "responseDns.h"
#include <errno.h>

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "buffer/buffer.h"
#include "socks5/socks5.h"
#include "parsers/dns/httpDnsParser.h"
#include "parsers/dns/dnsParser.h"
#include "netutils/netutils.h"
#include "states/stateUtilities/request/requestUtilities.h"

static void response_dns_on_arrival (SelectorEvent *event);
static unsigned response_dns_on_read(SelectorEvent *event);
static unsigned response_dns_on_write(SelectorEvent *event);

static void response_dns_on_arrival (SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;
    /* solo inicio los parsers de las sesiones que todavia esten abiertas, osea que pudieron establecer
     * conexion con el servidor dns */
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

/* Cuando ya se sabe que se termina en request error no se limpia nada extra 
 * y se deja que limpie el estado finish. Especialmente la estructura 
 * DnsHeaderContainer */

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

        /* si la otra conexion tambien es invalida estamos en problemas,
         * no se podra recuperar la ip del servidor pedido por el
         * cliente y se llega a un estado de error */
        if(!dnsHeaderOther->connected && dnsHeaderOther->dnsConnection.state == INVALID) {
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        } else if(dnsHeaderOther->connected) {
            return DNS_CONNECT;
        }
        

        /* si la otra conexion todavia puede ser valida solo me limpio yo y le dejo a
         * la otra conexion la posibilidad de obtener la ip del servidor pedido por el 
         * cliente */
        free(dnsHeaderMe->buffer.data);
        dnsHeaderMe->buffer.data = NULL;
        free(dnsHeaderMe->responseParser.addresses);
        dnsHeaderMe->responseParser.addresses = NULL;
        return session->sessionStateMachine.current;
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

    /*
     * Termine de parsar. 
     * - No necesito mas mi fd ni el buffer
     * - Tengo la lista con las IPs posibles
     **/
    selector_unregister_fd(event->s, event->fd);
    free(dnsHeaderMe->buffer.data);
    dnsHeaderMe->buffer.data = NULL;
    
    if (errored){
        
        /* si hubo un error y la otra conexion tambien es invalida estamos en problemas,
         * no se podra recuperar la ip del servidor pedido por el
         * cliente y se llega a un estado de error */
        if(!dnsHeaderOther->connected && dnsHeaderOther->dnsConnection.state == INVALID) {
            session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
            return REQUEST_ERROR;
        } else if(dnsHeaderOther->connected) {
            return DNS_CONNECT;
        }

        free(dnsHeaderMe->responseParser.addresses);
        dnsHeaderMe->responseParser.addresses = NULL;

        return session->sessionStateMachine.current;
    }

    if(dnsHeaderOther->connected){

        // Los dos termianron de parsear y el otro ya pudo hacer primer conncet ->  DNS_CONNECT
        // fprintf(stderr, "Leaving to DNS_CONNECT other connected. Fd: %d. Fd.State: %d. Client Fd: %d. State: %d\n", dnsHeaderMe->dnsConnection.fd, dnsHeaderMe->dnsConnection.state, session->clientConnection.fd, session->sessionStateMachine.current);

        return DNS_CONNECT;
    }

    /* debo probar una por una las ips obtenidas en el pedido dns hasta que pueda establecer la conexion con el servidor
     * por lo que con cada una se realizara un intento de conexion. Si el connect no falla, cuando nos vuelvan a llamar
     * en un estado proximo, revisaremos las opciones del socket para ver si verdaderamente sI la conexion sigue en proceso */

    do{
        if(dnsHeaderMe->responseParser.addresses[dnsHeaderMe->responseParser.counter].ipType == SOCKS_5_ADD_TYPE_IP4){
            session->serverConnection.fd =
                    new_ipv4_socket(dnsHeaderMe->responseParser.addresses[dnsHeaderMe->responseParser.counter++].addr.ipv4,
                            session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
        }
        else if(dnsHeaderMe->responseParser.addresses[dnsHeaderMe->responseParser.counter].ipType == SOCKS_5_ADD_TYPE_IP6) {
            session->serverConnection.fd =
                    new_ipv6_socket(dnsHeaderMe->responseParser.addresses[dnsHeaderMe->responseParser.counter++].addr.ipv6,
                            session->socksHeader.requestHeader.parser.port, (struct sockaddr *)&session->serverConnection.addr);
        }
        else {
            session->serverConnection.fd = 1;
        }

        if (session->serverConnection.fd  == -1) {
            session->socksHeader.requestHeader.rep = request_get_reply_value_from_errno(errno);
        }
    } while(session->serverConnection.fd  == -1 && dnsHeaderMe->responseParser.counter < dnsHeaderMe->responseParser.totalAnswers);

    /*
    * Salidas posibles
    * - fd == -1 -> probe toda la lista y ninguno pudo concetarse -> fin.
    * - fd != -1 -> pude hacer un primer conect. 
    *       - Si estyo solo -> me puedo ir
    *       - Si el otro esta activo -> espero que termine de parsear
    */

    if(session->serverConnection.fd  == -1) {

        if(dnsHeaderOther->dnsConnection.state == INVALID){
            // Mensaje de error viene de adentro del while. Error del ultimo intento de conexion. Hay que elegir uno.
            return REQUEST_ERROR;
        }

        free(dnsHeaderMe->responseParser.addresses);
        dnsHeaderMe->responseParser.addresses = NULL;
        return session->sessionStateMachine.current;
    }

    socks5_register_server(session);
    dnsHeaderMe->connected = true;
    selector_set_interest_event(event, OP_NOOP);

    if(dnsHeaderOther->dnsConnection.state == OPEN){
        // fprintf(stderr, "Connected, waiting for brother. Fd: %d. Fd.State: %d. Client Fd: %d. State: %d\n", dnsHeaderMe->dnsConnection.fd, dnsHeaderMe->dnsConnection.state, session->clientConnection.fd, session->sessionStateMachine.current);

        return session->sessionStateMachine.current;
    }

    // fprintf(stderr, "Leaving to DNS_CONNECT me connected. Fd: %d. Fd.State: %d. Client Fd: %d. State: %d\n", dnsHeaderMe->dnsConnection.fd, dnsHeaderMe->dnsConnection.state, session->clientConnection.fd, session->sessionStateMachine.current);

    return DNS_CONNECT;
}

static unsigned response_dns_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;
    DnsHeader *dnsHeaderMe, *dnsHeaderOther;

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

        return session->sessionStateMachine.current;
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
        .on_write = response_dns_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
