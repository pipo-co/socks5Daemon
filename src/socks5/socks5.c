#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "socks5.h"

#include "stateMachineBuilder/stateMachineBuilder.h"
#include "statistics/statistics.h"

#define DEFAULT_INPUT_BUFFER_SIZE 512
#define DEFAULT_OUTPUT_BUFFER_SIZE 512
#define DEFAULT_DNS_BUFFER_SIZE 512

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define ERROR(msg) perror(msg);

static Socks5Args * args;

static FdHandler clientHandler;
static FdHandler serverHandler;
// static FdHandler DNSHandler;

static int sessionInputBufferSize;
static int sessionOutputBufferSize;
static int dnsBufferSize;

static char *dnsServerIp;

static int stateLogCount;

static SessionHandlerP socks5_session_init(void);
static void socks5_server_read(SelectorEvent *event);
static void socks5_server_write(SelectorEvent *event);
static void socks5_server_close(SelectorEvent *event);
static void socks5_client_read(SelectorEvent *event);
static void socks5_client_write(SelectorEvent *event);
static void socks5_client_close(SelectorEvent *event);
static void socks5_close_session(SelectorEvent *event);
static int socks5_accept_connection(int passiveFd, struct sockaddr *cli_addr, socklen_t *clilen);

void socks5_init(Socks5Args *argsParam) {

    args = argsParam;
    stateLogCount = 0;

    sessionInputBufferSize = DEFAULT_INPUT_BUFFER_SIZE;
    sessionOutputBufferSize = DEFAULT_OUTPUT_BUFFER_SIZE;
    dnsBufferSize = dnsBufferSize;

    dnsServerIp = dnsServerIp;

    clientHandler.handle_read = socks5_client_read;
    clientHandler.handle_write = socks5_client_write;
    clientHandler.handle_close = socks5_client_close;
    clientHandler.handle_block = NULL;

    serverHandler.handle_read = socks5_server_read;
    serverHandler.handle_write = socks5_server_write;
    serverHandler.handle_close = socks5_server_close;
    serverHandler.handle_block = NULL;

    // serverHandler.handle_read = socks5_dns_read;
    // serverHandler.handle_write = socks5_dns_write;
    // serverHandler.handle_close = NULL;
    // serverHandler.handle_block = NULL;

    socks5_session_state_machine_builder_init();

    // Load Parsers
    auth_request_parser_load();
}

static int socks5_accept_connection(int passiveFd, struct sockaddr *cli_addr, socklen_t *clilen) {

    int fd;

    do {
        fd = accept(passiveFd, cli_addr, clilen);
    } while(fd < 0 && (errno == EINTR));
    
    if(fd < 0 ) {
        perror("Accept new client connection aborted");
    }

    return fd;
}

//tendría que haber otro passive accept para ipv6
void socks5_passive_accept_ipv4(SelectorEvent *event){
    
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    int fd = socks5_accept_connection(event->fd, (struct sockaddr *)&cli_addr, &clilen);

    if(fd < 0) {
        return;
    }

    SessionHandlerP session = socks5_session_init();

    session->clientConnection.fd = fd;

    memcpy(&session->clientConnection.addr, (struct sockaddr *)&cli_addr, clilen);

    selector_register(event->s, session->clientConnection.fd, &clientHandler, OP_READ, session);

    fprintf(stderr, "Registered new client %d\n", fd);
}

//tendría que haber otro passive accept para ipv6
void socks5_passive_accept_ipv6(SelectorEvent *event){
    
    struct sockaddr_in6 cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    int fd = socks5_accept_connection(event->fd, (struct sockaddr *)&cli_addr, &clilen);

    if(fd < 0) {
        return;
    }

    SessionHandlerP session = socks5_session_init();

    session->clientConnection.fd = fd;

    memcpy(&session->clientConnection.addr, (struct sockaddr *)&cli_addr, clilen);

    selector_register(event->s, session->clientConnection.fd, &clientHandler, OP_READ, session);
}

void socks5_register_server(FdSelector s, SessionHandlerP socks5_p){

    socks5_p->serverConnection.state = OPEN;

    selector_register(s, socks5_p->serverConnection.fd, &serverHandler, OP_WRITE, socks5_p);

    fprintf(stderr, "Registered new server %d\n", socks5_p->serverConnection.fd);
}

static void socks5_server_read(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    Buffer * buffer = &session->output;
    unsigned state;

    if(!buffer_can_write(buffer)) {
        fprintf(stderr, "ERROR: Read server socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

        socks5_close_session(event);
        return;
    }

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);


    if(readBytes = recv(event->fd, writePtr, nbytes, MSG_NOSIGNAL), readBytes >= 0) {
        buffer_write_adv(buffer, readBytes);

        if(readBytes == 0) {

            if(selector_state_machine_state(&session->sessionStateMachine) < FORWARDING) {
                fprintf(stderr, "ERROR: Unexpected Server Closing %d\n", session->clientConnection.fd);
                socks5_close_session(event);
                return;
            }

            session->serverConnection.state = CLOSING;
        }

        statistics_add_bytes_received(readBytes);
            
        if(state = selector_state_machine_proccess_read(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        fprintf(stderr, "%d: Server Read, State %ud\n", stateLogCount, state);
        stateLogCount++;
    }

    else {
        if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("Server Recv failed");
            socks5_close_session(event);
        }
    }
}

static void socks5_server_write(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    Buffer * buffer = &session->input;
    unsigned state;

    if(!buffer_can_read(buffer)) {
        fprintf(stderr, "Write server socket %d was registered on pselect, but there was nothing on buffer\n", event->fd);

        if(state = selector_state_machine_proccess_write(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        fprintf(stderr, "%d: Server Write, State %ud\n", stateLogCount, state);
        stateLogCount++;

        return;
    }
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if(writeBytes = send(event->fd, readPtr, nbytes, MSG_NOSIGNAL), writeBytes > 0) {
        buffer_read_adv(buffer, writeBytes);

        statistics_add_bytes_sent(writeBytes);

        if(state = selector_state_machine_proccess_write(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        fprintf(stderr, "%d: Server Write, State %ud\n", stateLogCount, state);
        stateLogCount++;
    }

    else if (writeBytes == 0){
        fprintf(stderr, "%d wrote 0 bytes\n", session->serverConnection.fd);
    }

    else {
        if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {

            if(errno == EPIPE) {
                fprintf(stderr, "Cierre forzoso de parte de server\n");
            }

            perror("Server Send failed");
            socks5_close_session(event);
        }
    }
}

static void socks5_client_read(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    Buffer * buffer = &session->input;
    unsigned state;

    if(!buffer_can_write(buffer)) {
        fprintf(stderr, "ERROR: Read client socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

        socks5_close_session(event);
        return;
    }

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);

    if(readBytes = recv(event->fd, writePtr, nbytes, MSG_NOSIGNAL), readBytes >= 0) {
        buffer_write_adv(buffer, readBytes);

        if(readBytes == 0) {

            if(selector_state_machine_state(&session->sessionStateMachine) < FORWARDING) {
                fprintf(stderr, "Unexpected Client Closing %d\n", session->clientConnection.fd);
                socks5_close_session(event);
                return;
            }

            session->clientConnection.state = CLOSING;
        }

        statistics_add_bytes_received(readBytes);

        if(state = selector_state_machine_proccess_read(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        fprintf(stderr, "%d: Client Read, State %ud\n", stateLogCount, state);
        stateLogCount++;
    }

    else {
        if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("Client Recv failed");
            socks5_close_session(event);
        }
    }
   
}

static void socks5_client_write(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    Buffer * buffer = &session->output;
    unsigned state;

    if(!buffer_can_read(buffer)) {
        fprintf(stderr, "Write client socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

        if(state = selector_state_machine_proccess_write(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        return;
    }
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if(writeBytes = send(event->fd, readPtr, nbytes, MSG_NOSIGNAL), writeBytes > 0){
        buffer_read_adv(buffer, writeBytes);

        statistics_add_bytes_sent(writeBytes);

        if(state = selector_state_machine_proccess_write(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        fprintf(stderr, "%d: Client Write, State %u\n", stateLogCount, state);
        stateLogCount++;
    }
    else if (writeBytes == 0){
        fprintf(stderr, "%d wrote 0 bytes\n", session->clientConnection.fd);
    }
    else
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {

            if(errno == EPIPE) {
                fprintf(stderr, "Cierre forzoso de parte de client\n");
            }

            perror("Client Send failed");
            socks5_close_session(event);
        }
    }
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

    session->clientConnection.state = OPEN;
    session->serverConnection.state = INVALID;

    return session;
}

static void socks5_client_close(SelectorEvent *event){
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    selector_state_machine_close(&session->sessionStateMachine, event);

    close(session->clientConnection.fd);

    free(session->input.data);
    free(session->output.data);
    free(session);
}

static void socks5_server_close(SelectorEvent *event) {
    close(event->fd);
}

static void socks5_close_session(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    statistics_dec_current_connection(false);

    if(session->clientInfo.user != NULL) {
        session->clientInfo.user->connectionCount--;

        if(session->clientInfo.user->connectionCount == 0) {
            statistics_dec_current_user_count();
        }
    }

    if(session->serverConnection.fd != INVALID) {
        selector_unregister_fd(event->s, session->serverConnection.fd);
    }

    selector_unregister_fd(event->s, session->clientConnection.fd);
}
