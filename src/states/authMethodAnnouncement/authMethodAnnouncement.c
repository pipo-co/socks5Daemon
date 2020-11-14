#include "authMethodAnnouncement.h"

#include <stdio.h>

#include "userHandler/userHandler.h"

#define HELLO_REPLY_SIZE 2

static void hello_marshall(Buffer *b, size_t * bytes, uint8_t method);
static void method_announcement_on_arrival(SelectorEvent *event);
static unsigned method_announcement_on_write(SelectorEvent *event);

static void method_announcement_on_arrival(SelectorEvent *event) {
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.helloHeader.bytes = 0;

    /* Primer escritura del mensaje antes de hacerle el primer send al cliente */
    hello_marshall(&session->output, &session->socksHeader.helloHeader.bytes, session->clientInfo.authMethod); 

    selector_set_interest_event(event, OP_WRITE);
}

static unsigned method_announcement_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.helloHeader.bytes == HELLO_REPLY_SIZE && !buffer_can_read(&session->output)) {

        if(session->clientInfo.authMethod == NO_AUTHENTICATION) {
            
            session->clientInfo.user = user_handler_get_user_by_username(ANONYMOUS_USER_CREDENTIALS);

            // Anonymous User Must Always Be Present
            if(session->clientInfo.user == NULL) {
                abort();
            }

            return REQUEST;
        }
        else {
            return AUTH_REQUEST;
        }
    }

    // Preparar buffer para proximo write 
    hello_marshall(&session->output, &session->socksHeader.helloHeader.bytes, session->clientInfo.authMethod); 

    return session->sessionStateMachine.current;
}

static void hello_marshall(Buffer *b, size_t * bytes, uint8_t method) {

    while(*bytes < HELLO_REPLY_SIZE && buffer_can_write(b)){
        if(*bytes == 0){
            buffer_write(b, SOCKS_VERSION);
        }
        if(*bytes == 1) {
            buffer_write(b, method);
        }
        (*bytes)++;
    }
}

SelectorStateDefinition auth_method_announcement_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_METHOD_ANNOUNCEMENT,
        .on_arrival = method_announcement_on_arrival,
        .on_read = NULL,
        .on_write = method_announcement_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
