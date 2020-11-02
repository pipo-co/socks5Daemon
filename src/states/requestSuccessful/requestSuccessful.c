#include "requestSuccessful.h"

static int request_marshall(Buffer *b, uint8_t *bytes){

        while(*bytes < REPLY_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, SUCCESS);
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

unsigned request_successful_on_pre_write(struct selector_key *key){
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    request_marshall(&socks5_p->output, socks5_p->socksHeader.requestHeader.bytes);  

    return socks5_p->stm.current; 

}

unsigned request_successful_on_post_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    if (socks5_p->socksHeader.requestHeader.bytes == REPLY_SIZE && buffer_can_read(&socks5_p->output))
    {
        selector_set_interest(key->s, socks5_p->serverConnection.fd, OP_READ|OP_WRITE);
        selector_set_interest_key(key, OP_READ|OP_WRITE);
        return FORWARDING;
    }
    return socks5_p->stm.current;

}

void auth_successful_on_departure(const unsigned state, struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    //depende de como manejemos la memoria tendriamos que liberar la estructura

}