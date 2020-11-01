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

void auth_successful_on_pre_write(struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    auth_marshall(&socks5_p->output, socks5_p->bytesSentAuth);  

    return socks5_p->stm.current; 

}

void auth_successful_on_post_write(struct selector_key *key){

     Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    if (socks5_p->bytesSentAuth == AUTH_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        return REQUEST;
    }
    return socks5_p->stm.current;

}

void auth_successful_on_departure(const unsigned state, struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    //depende de como manejemos la memoria tendriamos que liberar la estructura

}