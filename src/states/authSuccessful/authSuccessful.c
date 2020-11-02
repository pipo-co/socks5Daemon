#include "authSuccessful.h"

static int auth_marshall(Buffer *b, uint8_t *bytes){

        while(*bytes < AUTH_RESPONSE_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            if(*bytes == 1){
                buffer_write(b, SUCCESS);
            }
            *bytes++;
        }
    }

unsigned auth_successful_on_pre_write(struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    auth_marshall(&socks5_p->output, socks5_p->socksHeader.authRequestHeader.bytes);  
    
    return socks5_p->stm.current; 

}

unsigned auth_successful_on_post_write(struct selector_key *key){

     Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    if (socks5_p->socksHeader.authRequestHeader.bytes == AUTH_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_set_interest_key(key, OP_READ);
        return REQUEST;
    }
    return socks5_p->stm.current;

}

void auth_successful_on_departure(const unsigned state, struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    //depende de como manejemos la memoria tendriamos que liberar la estructura

}