#include "authRequest.h"

#include <string.h>

#include "parsers/authRequest/authRequestParser.h"

static void auth_request_on_arrival(SelectorEvent *event);
static unsigned auth_request_on_read(SelectorEvent *event);

static void auth_request_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    auth_request_parser_init(&session->socksHeader.authRequestHeader.parser);

    session->socksHeader.authRequestHeader.bytes = 0;

    selector_set_interest(event->s, session->clientConnection.fd, OP_READ);
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

    if(h->parser.version != AUTH_VERSION) {
        //loggear ("AuthRequest: Invalid version!")
        return AUTH_ERROR;
    }

    UserInfoP user = user_handler_get_user_by_username(h->parser.username);

    // User does not exist
    if(user == NULL) {
        return AUTH_ERROR;
    }

    // Password does not match
    if(strcmp(user->password, h->parser.password) != 0) {
        return AUTH_ERROR;
    }

    session->clientInfo.user = user;

    return AUTH_SUCCESSFUL;
}

SelectorStateDefinition auth_request_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_REQUEST,
        .on_arrival = auth_request_on_arrival,
        .on_read = auth_request_on_read,
        .on_write = NULL,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}