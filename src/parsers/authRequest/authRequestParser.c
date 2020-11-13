#include "authRequestParser.h"
#include "socksDefs.h"

#include <string.h>

static AuthRequestParserState auth_request_state_version(AuthRequestParser *p, uint8_t byte);
static AuthRequestParserState auth_request_state_ulen(AuthRequestParser *p, uint8_t byte);
static AuthRequestParserState auth_request_state_uname(AuthRequestParser *p, uint8_t byte);
static AuthRequestParserState auth_request_state_plen(AuthRequestParser *p, uint8_t byte);
static AuthRequestParserState auth_request_state_password(AuthRequestParser *p, uint8_t byte);
static void auth_request_parser_load(void);

typedef AuthRequestParserState (*AuthRequestStateFunction)(AuthRequestParser*, uint8_t);

static AuthRequestStateFunction stateFunctions[AUTH_REQUEST_PARSER_INVALID_STATE + 1];

static bool authIsParserLoaded = false;

static void auth_request_parser_load(void) {
    stateFunctions[AUTH_REQUEST_PARSER_VERSION]         = auth_request_state_version;
    stateFunctions[AUTH_REQUEST_PARSER_ULEN]            = auth_request_state_ulen;
    stateFunctions[AUTH_REQUEST_PARSER_UNAME]           = auth_request_state_uname;
    stateFunctions[AUTH_REQUEST_PARSER_PLEN]            = auth_request_state_plen;
    stateFunctions[AUTH_REQUEST_PARSER_PASSWORD]        = auth_request_state_password;
    stateFunctions[AUTH_REQUEST_PARSER_SUCCESS]         = NULL;
    stateFunctions[AUTH_REQUEST_PARSER_INVALID_STATE]   = NULL;

    authIsParserLoaded = true;
}

void auth_request_parser_init(AuthRequestParser *p) {

    if(!authIsParserLoaded) {
        auth_request_parser_load();
    }

    p->errorType = AUTH_REQUEST_VALID;
    p->currentState = AUTH_REQUEST_PARSER_VERSION;
}

AuthRequestParserState auth_request_parser_feed(AuthRequestParser *p, uint8_t byte){
    
    if(stateFunctions[p->currentState] != NULL)
        p->currentState = stateFunctions[p->currentState](p, byte);

    return p->currentState;
}

bool auth_request_parser_consume(Buffer *buffer, AuthRequestParser *p, bool *errored){

    uint8_t byte;

    while(!auth_request_parser_is_done(p->currentState, errored) && buffer_can_read(buffer)) {
        
        byte = buffer_read(buffer);
        auth_request_parser_feed(p, byte); 
    }

    return auth_request_parser_is_done(p->currentState, errored);
}

bool auth_request_parser_is_done(AuthRequestParserState state, bool *errored){
    
    if(errored != NULL) {
        if(state == AUTH_REQUEST_PARSER_INVALID_STATE) {
            *errored = true;
        }

        else {
            *errored = false;
        }
    }

    if(state == AUTH_REQUEST_PARSER_INVALID_STATE || state == AUTH_REQUEST_PARSER_SUCCESS) {
        return true;
    }

    return false;
}

char * auth_request_parser_error_message(AuthRequestParser *p) {
    
    switch(p->errorType){
        case AUTH_REQUEST_VALID:            return "No error"; break;
        case AUTH_REQUEST_INVALID_VERSION:  return "Invalid Version Provided"; break;
        case AUTH_REQUEST_INVALID_ULEN:     return "Invalid Username Length Provided (min 1)"; break;
        case AUTH_REQUEST_INVALID_PLEN:     return "Invalid Password Length Provided (min 1)"; break;
        default:                            return "Invalid State"; break;
    }
}

static AuthRequestParserState auth_request_state_version(AuthRequestParser *p,uint8_t byte) {

    if(byte != AUTH_VERSION) {
        p->errorType = AUTH_REQUEST_INVALID_VERSION;
        return AUTH_REQUEST_PARSER_INVALID_STATE;
    }

    p->version = byte;

    return AUTH_REQUEST_PARSER_ULEN;
}

static AuthRequestParserState auth_request_state_ulen(AuthRequestParser *p, uint8_t byte) {

    if(byte < 1) {
        p->errorType = AUTH_REQUEST_INVALID_ULEN;
        return AUTH_REQUEST_PARSER_INVALID_STATE;
    }

     p->ulen = byte;
     p->credentialCharPointer = 0;

    return AUTH_REQUEST_PARSER_UNAME;
}

static AuthRequestParserState auth_request_state_uname(AuthRequestParser *p, uint8_t byte) {

    p->username[p->credentialCharPointer++] = (char) byte;

    if(p->credentialCharPointer == p->ulen) {
        p->username[p->credentialCharPointer] = 0;
        return AUTH_REQUEST_PARSER_PLEN;
    }

    return AUTH_REQUEST_PARSER_UNAME;
}

static AuthRequestParserState auth_request_state_plen(AuthRequestParser *p, uint8_t byte) {

    if(byte < 1) {
        p->errorType = AUTH_REQUEST_INVALID_PLEN;
        return AUTH_REQUEST_PARSER_INVALID_STATE;
    }

     p->plen = byte;
     p->credentialCharPointer = 0;

    return AUTH_REQUEST_PARSER_PASSWORD;
}

static AuthRequestParserState auth_request_state_password(AuthRequestParser *p, uint8_t byte) {

    p->password[p->credentialCharPointer++] = (char) byte;

    if(p->credentialCharPointer == p->plen) {
        p->password[p->credentialCharPointer] = 0;
        return AUTH_REQUEST_PARSER_SUCCESS;
    }

    return AUTH_REQUEST_PARSER_PASSWORD;
}
