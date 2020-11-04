#include "authRequest.h"

#include "parsers/authRequest/authRequestParser.h"

static void auth_request_on_arrival(SelectorEvent *event);
static unsigned auth_request_on_read(SelectorEvent *event);

static void auth_request_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    auth_request_parser_init(&session->socksHeader.authRequestHeader.parser);

    session->socksHeader.authRequestHeader.bytes = 0;

    selector_set_interest_event(event, OP_READ);
}

static unsigned auth_request_on_read(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;
    AuthRequestHeader * h = &session->socksHeader.authRequestHeader;
    bool errored;

    if(!auth_request_parser_consume(&session->input, &h->parser, &errored)) {
        return session->sessionStateMachine.current;
    }

    if(errored == true) {
        // loggear ( auth_request_parser_error_message(socks5_p->auth_parser.current_state);)
        return AUTH_ERROR;
    }

    if(h->parser.version != SOCKS_VERSION) {
        //loggear ("AuthRequest: Invalid version!")
        return AUTH_ERROR;
    }

    int loginAns = 0; 
    //TODO falta login
    // loginAns = login(h->parser.ulen, h->parser.username, h->parser.plen, h->parser.password, &loginError);
    if(loginAns){
        
        return AUTH_SUCCESSFUL;
    }
    
    // loggear login_error(errored); 
    return AUTH_ERROR;
}

SelectorStateDefinition auth_request_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_REQUEST,
        .on_arrival = auth_request_on_arrival,
        .on_post_read = auth_request_on_read,
        .on_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}