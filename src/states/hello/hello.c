#include "hello.h"


static void on_auth_method(HelloParser *p, uint8_t currentMethod){
    
    uint8_t *previousMethod = (uint8_t *) p->data;

    uint8_t methodPriorityList[] = {0xFF, 0x00, 0x02};

    size_t prev = 0;
    size_t curr = 0;

    for (size_t i = 0; i < sizeof(methodPriorityList); i++){
        if(*previousMethod == methodPriorityList[i]){
            prev = i;
        }
        if(currentMethod == methodPriorityList[i]){
            curr = i;
        }
    }

    if(prev < curr){
        *previousMethod = currentMethod;
    }
}


void hello_on_arrival (const unsigned state, struct selector_key *key){
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    hello_parser_init(&socks5_p->socksHeader.helloHeader.parser, on_auth_method, &socks5_p->clientInfo.authMethod);
    socks5_p->socksHeader.helloHeader.bytes = 0;
}

unsigned hello_on_post_read(struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    bool errored;
    HelloHeader * h = &socks5_p->socksHeader.helloHeader;

    if(!hello_parser_consume(&socks5_p->input, &h->parser, &errored)){
        return socks5_p->stm.current;
    }
    if (errored == true){
        //loggear ( hello_parser_error_message(socks5_p->hello_parser.current_state);)
        selector_set_interest_key(key, OP_WRITE);
        return HELLO_ERROR;
    }

    if (h->parser.version != SOCKS_VERSION){
        //loggear ("Hello: Invalid version!")
        selector_set_interest_key(key, OP_WRITE);
        return HELLO_ERROR;
    }
    
    if (socks5_p->clientInfo.authMethod == NO_ACCEPTABLE_METHODS){
        //loggear ("Hello: No acceptable methods!")
        selector_set_interest_key(key, OP_WRITE);
        return HELLO_ERROR;
    }
    
    selector_set_interest_key(key, OP_WRITE);
    return AUTH_METHOD_ANNOUNCEMENT;
}