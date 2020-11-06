#include "requestError.h"

#define REQUEST_ERROR_SIZE 10

static void dns_request_error_marshall(Buffer *b, size_t *bytes, uint8_t rep);
static void dns_request_error_on_arrival(SelectorEvent *event);
static unsigned dns_request_error_on_write(SelectorEvent *event);

static void dns_request_error_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.dnsHeaderContainer.errorBytes = 0;

    dns_request_error_marshall(&session->output, &session->socksHeader.dnsHeaderContainer.errorBytes, session->socksHeader.dnsHeaderContainer.rep);  

    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
    selector_set_interest(event->s, session->socksHeader.dnsHeaderContainer.ipv4.dnsConnection.fd, OP_NOOP);
    selector_set_interest(event->s, session->socksHeader.dnsHeaderContainer.ipv6.dnsConnection.fd, OP_NOOP);
}

static unsigned dns_request_error_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if (session->socksHeader.requestHeader.bytes == REQUEST_ERROR_SIZE && !buffer_can_read(&session->output)) {
        return FINISH;
    }

    request_error_marshall(&session->output, &session->socksHeader.requestHeader.bytes, session->socksHeader.requestHeader.rep);

    return session->sessionStateMachine.current;
}

static void dns_request_error_marshall(Buffer *b, size_t *bytes, uint8_t rep) {

        while(*bytes < REQUEST_ERROR_SIZE && buffer_can_write(b)) {
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, rep);
            }
            else if (*bytes == 2){
                buffer_write(b, RSV);
            }
            else if (*bytes == 3){
                buffer_write(b, ATYP);
            }
            else {
                buffer_write(b, 0);
            }
            (*bytes)++;
        }
    }

SelectorStateDefinition dns_request_error_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_ERROR,
        .on_arrival = dns_request_error_on_arrival,
        .on_read = NULL,
        .on_write = dns_request_error_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}