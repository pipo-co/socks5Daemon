#include "requestError.h"

static int request_error_marshall(Buffer *b, uint8_t *bytes, uint8_t rep){

        while(*bytes < REPLY_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, rep);
            }
            else if (*bytes == 2){
                buffer_write(b, RSV);
            }
            else if (*bytes == 3){
                buffer_write(b, ATYP);
            }
            else {
                buffer_write(b, 0);
            }
            *bytes++;
        }
    }

unsigned request_error_on_pre_write(struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    request_error_marshall(&socks5_p->output, socks5_p->socksHeader.requestHeader.bytes, socks5_p->socksHeader.requestHeader.rep);  
    
    return socks5_p->stm.current; 

}

unsigned request_error_on_post_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    if (socks5_p->socksHeader.requestHeader.bytes == REQUEST_ERROR_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_unregister_fd(key->s, key->fd);
        return FINNISH;
    }
    return socks5_p->stm.current;

}