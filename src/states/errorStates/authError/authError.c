#include "authError.h"

static int auth_error_marshall(Buffer *b, uint8_t *bytes){

        while(*bytes < AUTH_ERROR_RESPONSE_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            if(*bytes == 1){
                buffer_write(b, UNSUCCESSFUL);
            }
            *bytes++;
        }
    }

unsigned auth_error_on_pre_write(struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    auth_error_marshall(&socks5_p->output, socks5_p->socksHeader.authRequestHeader.bytes);  
    
    return socks5_p->stm.current; 

}

unsigned auth_error_on_post_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    if (socks5_p->socksHeader.authRequestHeader.bytes == AUTH_ERROR_RESPONSE_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_unregister_fd(key->s, key->fd);
        return FINNISH;
    }
    return socks5_p->stm.current;

}