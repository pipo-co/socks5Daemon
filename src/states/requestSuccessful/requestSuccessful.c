#include "requestSuccessful.h"

#include <time.h>
#include <stdio.h>

#include "netutils/netutils.h"
#include "states/stateUtilities/request/requestUtilities.h"

static void request_successful_on_arrival(SelectorEvent *event);
static unsigned request_successful_on_write(SelectorEvent *event);

static void request_successful_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.requestHeader.bytes = 0;
    session->socksHeader.requestHeader.rep = SUCCESSFUL;
    
    /* Primer escritura del mensaje antes de hacerle el primer send al cliente */
    request_marshall(&session->output, &session->socksHeader.requestHeader.bytes, session->socksHeader.requestHeader.rep);  

    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
    selector_set_interest(event->s, session->serverConnection.fd, OP_NOOP);
}

static unsigned request_successful_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;
   
    size_t *bytes = &session->socksHeader.requestHeader.bytes;
    ReplyValues rep = session->socksHeader.requestHeader.rep;

    if(request_marshall(&session->output, bytes, rep)) {

        log_user_access(session, rep);
        return FORWARDING;
    }

    return session->sessionStateMachine.current;
}

SelectorStateDefinition request_successful_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_SUCCESSFUL,
        .on_arrival = request_successful_on_arrival,
        .on_read = NULL,
        .on_write = request_successful_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}