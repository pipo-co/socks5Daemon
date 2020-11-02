#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "socks5.h"

#include "stateMachineBuilder.h"

#define DEFAULT_INPUT_BUFFER_SIZE 512
#define DEFAULT_OUTPUT_BUFFER_SIZE 512
#define DEFAULT_DNS_BUFFER_SIZE 512

#define ERROR(msg) perror(msg);

static FdHandler clientHandler;
static FdHandler serverHandler;
static FdHandler DNSHandler;

static int sessionInputBufferSize;
static int sessionOutputBufferSize;
static int dnsBufferSize;

static char *dnsServerIp; 


static SessionHandlerP socks5_session_init(void);
static void socks5_session_destroy(SessionHandlerP session);

void socks5_init(char *dnsServerIp) {
    sessionInputBufferSize = DEFAULT_INPUT_BUFFER_SIZE;
    sessionOutputBufferSize = DEFAULT_OUTPUT_BUFFER_SIZE;
    dnsBufferSize = dnsBufferSize;

    dnsServerIp = dnsServerIp;

    clientHandler.handle_read = socks5_client_read;
    clientHandler.handle_write = socks5_client_write;
    clientHandler.handle_close = NULL;
    clientHandler.handle_block = NULL;

    serverHandler.handle_read = socks5_server_read;
    serverHandler.handle_write = socks5_server_write;
    serverHandler.handle_close = NULL;
    serverHandler.handle_block = NULL;

    // serverHandler.handle_read = socks5_dns_read;
    // serverHandler.handle_write = socks5_dns_write;
    // serverHandler.handle_close = NULL;
    // serverHandler.handle_block = NULL;

    socks5_session_state_machine_builder_init();
}

static void socks5_server_read(struct SelectorEvent *key){

    SessionHandlerP socks5_p = (SessionHandlerP) key->data;
    Buffer * buffer = &socks5_p->output;
    
    //pre_read(socks5_p->stm, key)

    if(!buffer_can_write(buffer))
        return;

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);

    if((readBytes = read(key->fd, writePtr, nbytes) > 0)){
        buffer_write_adv(buffer, readBytes);
        state_machine_proccess_post_read(&socks5_p->sessionStateMachine, key);
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

static void socks5_server_write(struct SelectorEvent *key){

    SessionHandlerP socks5_p = (SessionHandlerP) key->data;

    state_machine_proccess_pre_write(&socks5_p->sessionStateMachine, key);

    Buffer * buffer = &socks5_p->input;

    if(!buffer_can_read(buffer))
        return;
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if( (writeBytes = write(key->fd, readPtr, nbytes)) > 0){
        buffer_read_adv(buffer, writeBytes);
        state_machine_proccess_post_write(&socks5_p->sessionStateMachine, key);
    }
    else if (writeBytes == 0){
        
    }
    else
    {
        //cerrar conexion
        //logger stderr(errno)
    }
    
}

void socks5_register_server(FdSelector s, SessionHandlerP socks5_p){
    
    FdHandler handler;
    handler.handle_read = socks5_server_read;
    handler.handle_write = socks5_server_write;

    selector_register(s, socks5_p->serverConnection.fd, &handler, OP_WRITE, &socks5_p);
    
}

static void socks5_client_read(struct SelectorEvent *key){

    SessionHandlerP socks5_p = (SessionHandlerP) key->data;
    Buffer * buffer = &socks5_p->input;
    
    //pre_read(socks5_p->stm, key)

    if(!buffer_can_write(buffer))
        return;

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);

    if((readBytes = read(key->fd, writePtr, nbytes) > 0)){
        buffer_write_adv(buffer, readBytes);
        state_machine_proccess_post_read(&socks5_p->sessionStateMachine, key);
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

static void socks5_client_write(struct SelectorEvent *key){
    
    
    SessionHandlerP socks5_p = (SessionHandlerP) key->data;

    state_machine_proccess_pre_write(&socks5_p->sessionStateMachine, key);

    Buffer * buffer = &socks5_p->output;

    if(!buffer_can_read(buffer))
        return;
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if( (writeBytes = write(key->fd, readPtr, nbytes)) > 0){
        buffer_read_adv(buffer, writeBytes);
        state_machine_proccess_post_write(&socks5_p->sessionStateMachine, key);
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
void socks5_passive_accept(SelectorEvent *event){
    
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    int fd = accept(event->fd,(struct sockaddr *)&cli_addr, &clilen);
    
    if (fd < 0 ){}
       //logger stderr(errno)

    SessionHandlerP session = socks5_session_init();

    session->clientConnection.fd = fd;

    memcpy(&session->clientConnection.addr, (struct sockaddr *)&cli_addr, clilen);

    selector_register(event->s, session->clientConnection.fd, &clientHandler, OP_READ, session);
}

static SessionHandlerP socks5_session_init(void) {

    SessionHandlerP session = calloc(1, sizeof(*session));
    if(session == NULL)
        return NULL;

    uint8_t *inputBuffer = malloc(sessionInputBufferSize*sizeof(*inputBuffer));
    if(inputBuffer == NULL)
        return NULL;
        
    uint8_t *outputBuffer = malloc(sessionOutputBufferSize*sizeof(*outputBuffer));
    if(outputBuffer == NULL)
        return NULL;

    buffer_init(&session->input, sessionInputBufferSize, inputBuffer);
    buffer_init(&session->output, sessionOutputBufferSize, outputBuffer);

    build_socks_session_state_machine(&session->sessionStateMachine);

    // session->sessionStateMachine.states[FINISH].on_departure = socks5_session_destroy;

    session->clientConnection.closed = false;

    return session;
}

static void socks5_session_destroy(SessionHandlerP session) {

    free(session->input.data);
    free(session->output.data);
    free(session);
}


