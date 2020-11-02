#include "ipConnect.h"


unsigned ip_connect_on_post_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    int error;
    socklen_t len;

    if(getsockopt(socks5_p->serverConnection.fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1){
        selector_unregister_fd(key->s, socks5_p->serverConnection.fd);
        selector_set_interest_key(key, OP_WRITE);
        //logger stderr(errno);
        socks5_p->socksHeader.requestHeader.rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR;
    }
    if(error == 0){
        selector_set_interest(key->s, socks5_p->serverConnection.fd, OP_NOOP);
        selector_set_interest_key(key, OP_WRITE);
        return REQUEST_SUCCESS; 
    }
    
        //logger stderr(error)???????????????
        selector_unregister_fd(key->s, socks5_p->serverConnection.fd);
        selector_set_interest_key(key, OP_WRITE);
        socks5_p->rep = GENERAL_SOCKS_SERVER_FAILURE;
        return REQUEST_ERROR; 
}
