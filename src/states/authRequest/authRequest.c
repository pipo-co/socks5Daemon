#include "authRequest.h"

#include "authRequestParser.h"

static void auth_request_on_arrival(SelectorEvent *event);
static unsigned auth_request_on_post_read(SelectorEvent *event);

static void auth_request_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    auth_request_parser_init(&socks5_p->socksHeader.authRequestHeader.parser);
    socks5_p->socksHeader.authRequestHeader.bytes = 0;
}

static unsigned auth_request_on_post_read(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;
    AuthRequestHeader * h = &socks5_p->socksHeader.authRequestHeader;
    bool errored;

    if(!auth_request_parser_consume(&socks5_p->input, &h->parser, &errored)){
        return socks5_p->sessionStateMachine.current;
    }
    if(errored == true){
        // loggear ( auth_request_parser_error_message(socks5_p->auth_parser.current_state);)
        selector_set_interest_event(event, OP_WRITE);
        return AUTH_ERROR;
    }
    if (h->parser.version != SOCKS_VERSION){
        //loggear ("AuthRequest: Invalid version!")
        selector_set_interest_event(event, OP_WRITE);
        return AUTH_ERROR;
    }
    int loginAns = 0; 
    //TODO falta login
    // loginAns = login(h->parser.ulen, h->parser.username, h->parser.plen, h->parser.password, &loginError);
    if (loginAns){
        
        selector_set_interest_event(event, OP_WRITE);
        return AUTH_SUCCESSFUL;
    }
    
    // loggear login_error(errored); 
    selector_set_interest_event(event, OP_WRITE);
    return AUTH_ERROR;
}

SelectorStateDefinition auth_request_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_REQUEST,
        .on_arrival = auth_request_on_arrival,
        .on_post_read = auth_request_on_post_read,
        .on_pre_write = NULL,
        .on_post_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}