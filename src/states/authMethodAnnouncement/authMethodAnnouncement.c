#include "authMethodAnnouncement.h"

static int hello_marshall(Buffer *b, uint8_t method, uint8_t *bytes){

        while(*bytes < INITIAL_RESPONSE_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            if(*bytes == 1){
                buffer_write(b, method);
            }
            *bytes++;
        }
    }

unsigned method_announcement_on_pre_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    hello_marshall(&socks5_p->output, socks5_p->clientInfo.authMethod, socks5_p->socksHeader.helloHeader.bytes);  

    return socks5_p->stm.current;  
}

unsigned method_announcement_on_post_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    if (socks5_p->socksHeader.helloHeader.bytes == INITIAL_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_set_interest_key(key, OP_READ);
        if(socks5_p->clientInfo.authMethod == NO_AUTHENTICATION){
            //cargar credenciales del usuario anonimo
            return REQUEST;
        }
        else
        {
            return AUTH_REQUEST;
        }
    }
    return socks5_p->stm.current;
}

void method_announcement_on_departure(const unsigned state, struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    //depende de como manejemos la memoria tendriamos que liberar la estructura

}


