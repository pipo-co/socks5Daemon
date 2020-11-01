#include "authRequest.h"

void auth_request_on_arrival (const unsigned state, struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    auth_request_parser_init(&socks5_p->authRequestParser);
}

unsigned auth_request_on_post_read(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    bool errored;
    uint8_t logginError;

    if(!auth_request_parser_consume(&socks5_p->input, &socks5_p->authRequestParser, &errored)){
        return socks5_p->stm.current;
    }
    if(errored == true){
        //loggear ( auth_request_parser_error_message(socks5_p->auth_parser.current_state);)
        return AUTH_ERROR;
    }
    if (socks5_p->authRequestParser.version != SOCKS_VERSION){
        //loggear ("AuthRequest: Invalid version!")
        return AUTH_ERROR;
    }

    if (loggin(socks5_p->authRequestParser.ulen, socks5_p->authRequestParser.username, socks5_p->authRequestParser.plen, socks5_p->authRequestParser.password, &logginError)){
        
        return AUTH_SUCCESSFUL;
    }
    
    //loggear loggin_error(errored); 
    return AUTH_ERROR;
}