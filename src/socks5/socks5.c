#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "socks5.h"

#define ERROR(msg) perror(msg);

enum SocksSizeConstants {
  MAX_CONNECTIONS = 1024,
  BUFSIZE = 512,
  MAX_METHODS = 255
};

typedef struct{
    Socks5Handler   handler;
    uint8_t         asigned;
} Socks5HandlerHeader;

Socks5HandlerHeader connections[MAX_CONNECTIONS];


static void socks5_server_read(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    Buffer * buffer = &socks5_p->output;
    
    //pre_read(socks5_p->stm, key)

    if(!buffer_can_write(buffer))
        return;

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);

    if((readBytes = read(key->fd, writePtr, nbytes) > 0)){
        buffer_write_adv(buffer, readBytes);
        state_machine_proccess_post_read(&socks5_p->stm, key);
    }
    else if (readBytes == 0){
        //server cerro conexion
    }
    else
    {
        //cerrar conexion
        //logger stderr(errno)
    }
      
}

static void socks5_server_write(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    state_machine_proccess_pre_write(&socks5_p->stm, key);

    Buffer * buffer = &socks5_p->input;

    if(!buffer_can_read(buffer))
        return;
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if( (writeBytes = write(key->fd, readPtr, nbytes)) > 0){
        buffer_read_adv(buffer, writeBytes);
        state_machine_proccess_post_write(&socks5_p->stm, key);
    }
    else if (writeBytes == 0){
        
    }
    else
    {
        //cerrar conexion
        //logger stderr(errno)
    }
    
}

void socks5_register_server(fd_selector s, Socks5HandlerP socks5_p){
    
    fd_handler handler;
    handler.handle_read = socks5_server_read;
    handler.handle_write = socks5_server_write;

    selector_register(s, socks5_p->serverConnection.fd, &handler, OP_WRITE, &socks5_p);
    
}

static void socks5_client_read(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;
    Buffer * buffer = &socks5_p->input;
    
    //pre_read(socks5_p->stm, key)

    if(!buffer_can_write(buffer))
        return;

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);

    if((readBytes = read(key->fd, writePtr, nbytes) > 0)){
        buffer_write_adv(buffer, readBytes);
        state_machine_proccess_post_read(&socks5_p->stm, key);
    }
    else if (readBytes == 0){
        //cliente cerro conexion
    }
    else
    {
        //cerrar conexion
        //logger stderr(errno)
    }
   
}

static void socks5_client_write(struct selector_key *key){
    
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    state_machine_proccess_pre_write(&socks5_p->stm, key);

    Buffer * buffer = &socks5_p->output;

    if(!buffer_can_read(buffer))
        return;
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if( (writeBytes = write(key->fd, readPtr, nbytes)) > 0){
        buffer_read_adv(buffer, writeBytes);
        state_machine_proccess_post_write(&socks5_p->stm, key);
    }
    else if (writeBytes == 0){

    }
    else
    {
        //cerrar conexion
        //logger stderr(errno)
    }
}

//tendria que haber otro passive accept para ipv6
void socks5_passive_accept(struct selector_key *key){
    
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    int fd = accept(key->fd,(struct sockaddr *)&cli_addr, &clilen);
    
    if (fd < 0 ){}
       //logger stderr(errno)

    Socks5HandlerP socks5_p = malloc(sizeof(*socks5_p));
    


    buffer_init(&socks5_p->input, sizeof(socks5_p->rawBufferInput), socks5_p->rawBufferInput);
    buffer_init(&socks5_p->output, sizeof(socks5_p->rawBufferOutput), socks5_p->rawBufferOutput);

    socks5_p->fd_handler.handle_read = socks5_client_read;
    socks5_p->fd_handler.handle_write = socks5_client_write;
    
    state_machine_init(&socks5_p->stm);

    socks5_p->clientConnection.fd = fd;
    memcpy(&socks5_p->clientConnection.addr, (struct sockaddr *)&cli_addr, clilen);


    bzero(&socks5_p->serverConnection, sizeof(socks5_p->serverConnection));

    bzero(&socks5_p->clientInfo, sizeof(socks5_p->clientInfo));

    bzero(&socks5_p->socksHeader, sizeof(socks5_p->socksHeader));

    selector_register(key->s, socks5_p->clientConnection.fd, &socks5_p->fd_handler, OP_READ, socks5_p);
}


