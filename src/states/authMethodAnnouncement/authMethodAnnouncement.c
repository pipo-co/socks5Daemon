#include "authMethodAnnouncement.h"

#define INITIAL_RESPONSE_SIZE 2

static void hello_marshall(Buffer *b, uint8_t method, size_t *bytes);
static unsigned method_announcement_on_pre_write(struct SelectorEvent *key);
static unsigned method_announcement_on_post_write(struct SelectorEvent *key);

static unsigned method_announcement_on_pre_write(struct SelectorEvent *key) {

    SessionHandlerP socks5_p = (SessionHandlerP) key->data;

    hello_marshall(&socks5_p->output, socks5_p->clientInfo.authMethod, &socks5_p->socksHeader.helloHeader.bytes);  

    return socks5_p->sessionStateMachine.current;  
}

static unsigned method_announcement_on_post_write(struct SelectorEvent *key) {

    SessionHandlerP socks5_p = (SessionHandlerP) key->data;

    if (socks5_p->socksHeader.helloHeader.bytes == INITIAL_RESPONSE_SIZE && !buffer_can_read(&socks5_p->output))
    {
        selector_set_interest_event(key, OP_READ);
        if(socks5_p->clientInfo.authMethod == NO_AUTHENTICATION){
            //TODO: cargar credenciales del usuario anonimo
            return REQUEST;
        }
        else
        {
            return AUTH_REQUEST;
        }
    }
    return socks5_p->sessionStateMachine.current;
}

static void hello_marshall(Buffer *b, uint8_t method, size_t * bytes) {

    while(*bytes < INITIAL_RESPONSE_SIZE && buffer_can_write(b)){
        if(*bytes == 0){
            buffer_write(b, SOCKS_VERSION);
        }
        if(*bytes == 1){
            buffer_write(b, method);
        }
        (*bytes)++;
    }
}

SelectorStateDefinition auth_method_announcement_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = AUTH_METHOD_ANNOUNCEMENT,
        .on_arrival = NULL,
        .on_post_read = NULL,
        .on_pre_write = method_announcement_on_pre_write,
        .on_post_write = method_announcement_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}
