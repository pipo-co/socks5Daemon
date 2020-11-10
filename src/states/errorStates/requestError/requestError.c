#include "requestError.h"

#include "states/stateUtilities/request/requestUtilities.h"


static void request_error_on_arrival(SelectorEvent *event);
static unsigned request_error_on_write(SelectorEvent *event);

static void request_error_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.requestHeader.bytes = 0;

    // TODO revisar validez
    if(session->socksHeader.requestHeader.rep == SUCCESSFUL){
        session->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
    }

    request_marshall(&session->output, &session->socksHeader.requestHeader.bytes, session->socksHeader.requestHeader.rep);  

    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
}

static unsigned request_error_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;
    
    size_t *bytes = &session->socksHeader.requestHeader.bytes;
    ReplyValues rep = session->socksHeader.requestHeader.rep;

    if(request_marshall(&session->output, bytes, rep)) {

        log_user_access(session, rep);
        return FINISH;
    }

    return session->sessionStateMachine.current;
}

SelectorStateDefinition request_error_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_ERROR,
        .on_arrival = request_error_on_arrival,
        .on_read = NULL,
        .on_write = request_error_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}