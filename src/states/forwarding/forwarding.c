#include "forwarding.h"

static void forwarding_on_arrival(SelectorEvent *event);
static unsigned forwarding_on_post_read(SelectorEvent *event);
static unsigned forwarding_on_post_write(SelectorEvent *event);

static void forwarding_on_arrival(SelectorEvent *event){
    //Init sniffing structure
}

static unsigned forwarding_on_post_read(SelectorEvent *event) {
    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    if(socks5_p->clientConnection.state != OPEN || socks5_p->serverConnection.state != OPEN)
        return FLUSH_CLOSER; 

    size_t nbytes;
    uint8_t * buff;
    bool buffCanWrite, isServer = false;

    if(event->fd == socks5_p->serverConnection.fd){
        buff = buffer_read_ptr(&socks5_p->output, &nbytes);
        buffCanWrite = buffer_can_write(&socks5_p->output);
        isServer = true;
    } 
    else
    {
        buff = buffer_read_ptr(&socks5_p->input, &nbytes);
        buffCanWrite = buffer_can_write(&socks5_p->input);
    }

    if(!buffCanWrite) {
        // no puedo escribir mas al buffer de input, me despierten mas por read
        remove_interest(event->s, event->fd, OP_READ);
    }
 
    if(nbytes != 0){
        if(isServer){
            //como tengo espacio en el buffer de lectura, me interesa que me escriban, desperta al que me escribe por write
            add_interest(event->s, socks5_p->clientConnection.fd, OP_WRITE);
        }
        else{
            add_interest(event->s, socks5_p->serverConnection.fd, OP_WRITE);
        }   
    }

    // while (nbytes > 0) {
    //     //process buffer information
    //     nbytes--;
    // }

    return socks5_p->sessionStateMachine.current;
    
}

static unsigned forwarding_on_post_write(SelectorEvent *event) {

    SessionHandlerP socks5_p = (SessionHandlerP) event->data;

    bool buffCanWrite, buffCanRead, isServer = false;

    if(event->fd == socks5_p->serverConnection.fd){
        buffCanRead = buffer_can_read(&socks5_p->input);
        buffCanWrite = buffer_can_write(&socks5_p->input);
        isServer = true;
    } 
    else
    {
        buffCanRead = buffer_can_read(&socks5_p->output);
        buffCanWrite = buffer_can_write(&socks5_p->output);
    }

    if(buffCanWrite){
        if(isServer){
            //ya tengo lugar en el buffer de output, el contrario puede seguir cargandome
            add_interest(event->s, socks5_p->clientConnection.fd, OP_READ);
        }
        else{
            add_interest(event->s, socks5_p->serverConnection.fd, OP_READ);
        }   
    }
    if(!buffCanRead){
        //Ya lei todo asi que no me llames mas por lectura
        remove_interest(event->s, event->fd, OP_WRITE);
    }

    return socks5_p->sessionStateMachine.current;
}

SelectorStateDefinition forwarding_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = FORWARDING,
        .on_arrival = forwarding_on_arrival,
        .on_post_read = forwarding_on_post_read,
        .on_pre_write = NULL,
        .on_post_write = forwarding_on_post_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}