#include "authRequest.h"

void auth_request_on_arrival (const unsigned state, struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    auth_request_parser_init(&socks5_p->socksHeader.authRequestHeader.parser);
    socks5_p->socksHeader.authRequestHeader.bytes = 0;
}

unsigned auth_request_on_post_read(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    AuthRequestHeader * h = &socks5_p->socksHeader.authRequestHeader;
    bool errored;
    uint8_t logginError;

    if(!auth_request_parser_consume(&socks5_p->input, &h->parser, &errored)){
        return socks5_p->stm.current;
    }
    if(errored == true){
        //loggear ( auth_request_parser_error_message(socks5_p->auth_parser.current_state);)
        selector_set_interest_key(key, OP_WRITE);
        return AUTH_ERROR;
    }
    if (h->parser.version != SOCKS_VERSION){
        //loggear ("AuthRequest: Invalid version!")
        selector_set_interest_key(key, OP_WRITE);
        return AUTH_ERROR;
    }

    if (loggin(h->parser.ulen, h->parser.username, h->parser.plen, h->parser.password, &logginError)){
        
        selector_set_interest_key(key, OP_WRITE);
        return AUTH_SUCCESSFUL;
    }
    
    //loggear loggin_error(errored); 
    selector_set_interest_key(key, OP_WRITE);
    return AUTH_ERROR;
}