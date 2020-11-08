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
#include "netutils/netutils.h"
#include "stateMachineBuilder/stateMachineBuilder.h"
#include "statistics/statistics.h"

#define DEFAULT_INPUT_BUFFER_SIZE 512
#define DEFAULT_OUTPUT_BUFFER_SIZE 512
#define DEFAULT_DNS_BUFFER_SIZE 512

#define N(x) (sizeof(x)/sizeof((x)[0]))

static Socks5Args * args;

static FdHandler clientHandler;
static FdHandler serverHandler;
static FdHandler DNSHandler;

static uint32_t sessionInputBufferSize;
static uint32_t sessionOutputBufferSize;
static uint32_t dnsBufferSize;

static double maxSessionInactivity;

static int stateLogCount;

static SessionHandlerP socks5_session_init(void);
static void socks5_server_read(SelectorEvent *event);
static void socks5_server_write(SelectorEvent *event);
static void socks5_server_close(SelectorEvent *event);
static void socks5_dns_read(SelectorEvent *event);
static void socks5_dns_write(SelectorEvent *event);
static void socks5_dns_close(SelectorEvent *event);
static void socks5_client_read(SelectorEvent *event);
static void socks5_client_write(SelectorEvent *event);
static void socks5_client_close(SelectorEvent *event);
static void socks5_close_session(SelectorEvent *event);
static int socks5_accept_connection(int passiveFd, struct sockaddr *cli_addr, socklen_t *clilen);

void socks5_init(Socks5Args *argsParam, double maxSessionInactivityParam) {

    args = argsParam;
    stateLogCount = 0;
    maxSessionInactivity = maxSessionInactivityParam;

    sessionInputBufferSize = DEFAULT_INPUT_BUFFER_SIZE;
    sessionOutputBufferSize = DEFAULT_OUTPUT_BUFFER_SIZE;
    dnsBufferSize = dnsBufferSize;

    clientHandler.handle_read = socks5_client_read;
    clientHandler.handle_write = socks5_client_write;
    clientHandler.handle_close = socks5_client_close;
    clientHandler.handle_block = NULL;

    serverHandler.handle_read = socks5_server_read;
    serverHandler.handle_write = socks5_server_write;
    serverHandler.handle_close = socks5_server_close;
    serverHandler.handle_block = NULL;

    DNSHandler.handle_read = socks5_dns_read;
    DNSHandler.handle_write = socks5_dns_write;
    DNSHandler.handle_close = socks5_dns_close;
    DNSHandler.handle_block = NULL;

    socks5_session_state_machine_builder_init();

    // Load Parsers
    auth_request_parser_load();
}

static int socks5_accept_connection(int passiveFd, struct sockaddr *cli_addr, socklen_t *clilen) {

    int fd;

    do {
        fd = accept(passiveFd, cli_addr, clilen);
    } while(fd < 0 && (errno == EINTR));

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
    if(session == NULL) {
        close(fd);
        fprintf(stderr, "Session initialization failed: Not enough memory.\n");
        return;
    }

    session->clientConnection.fd = fd;

    memcpy(&session->clientConnection.addr, (struct sockaddr *)&cli_addr, clilen);

    selector_register(event->s, session->clientConnection.fd, &clientHandler, OP_READ, session);

    // fprintf(stderr, "Registered new client %d\n", fd);
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
    if(session == NULL) {
        close(fd);
        // fprintf(stderr, "Session initialization failed: Not enough memory.\n");
        return;
    }

    session->clientConnection.fd = fd;

    memcpy(&session->clientConnection.addr, (struct sockaddr *)&cli_addr, clilen);

    selector_register(event->s, session->clientConnection.fd, &clientHandler, OP_READ, session);
}

void socks5_register_server(FdSelector s, SessionHandlerP session){

    session->serverConnection.state = OPEN;
    statistics_inc_current_connection();

    selector_register(s, session->serverConnection.fd, &serverHandler, OP_WRITE, session);

    // fprintf(stderr, "Registered new server %d\n", session->serverConnection.fd);
}

void socks5_register_dns(FdSelector s, SessionHandlerP session){

    if(session->dnsHeaderContainer->ipv4.dnsConnection.state == OPEN) {
        statistics_inc_current_connection();
        selector_register(s, session->dnsHeaderContainer->ipv4.dnsConnection.fd, &DNSHandler, OP_WRITE, session);
        // fprintf(stderr, "IPv4 - Registered new dns. Fd: %d. Session %p. Client Fd: %d.\n", session->dnsHeaderContainer->ipv4.dnsConnection.fd, (void *) session, session->clientConnection.fd);
    }

    if(session->dnsHeaderContainer->ipv6.dnsConnection.state == OPEN) {
        statistics_inc_current_connection();
        selector_register(s, session->dnsHeaderContainer->ipv6.dnsConnection.fd, &DNSHandler, OP_WRITE, session);
        // fprintf(stderr, "IPv6 - Registered new dns. Fd: %d. Session %p. Client Fd: %d.\n", session->dnsHeaderContainer->ipv6.dnsConnection.fd, (void *)session, session->clientConnection.fd);
    }
}

Socks5Args *socks5_get_args(void){
    return args;
}

static void socks5_server_read(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->lastInteraction = time(NULL);

    Buffer * buffer = &session->output;
    unsigned state;

    if(!buffer_can_write(buffer)) {
        // fprintf(stderr, "ERROR: Read server socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

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
                // fprintf(stderr, "ERROR: Unexpected Server Closing %d\n", session->clientConnection.fd);
                socks5_close_session(event);
                return;
            }

            session->serverConnection.state = CLOSING;
        }

        statistics_add_bytes_received(readBytes);
            
        if(state = selector_state_machine_proccess_read(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        // fprintf(stderr, "%d: Server Read, State %ud\n", stateLogCount, state);
        stateLogCount++;
    }

    else {
        if(errno != EINTR) {
            socks5_close_session(event);
        }
    }
}

static void socks5_server_write(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->lastInteraction = time(NULL);

    Buffer * buffer = &session->input;
    unsigned state;

    if(!buffer_can_read(buffer)) {
        // fprintf(stderr, "Write server socket %d was registered on pselect, but there was nothing on buffer\n", event->fd);

        if(state = selector_state_machine_proccess_write(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        // fprintf(stderr, "%d: Server Write, State %ud\n", stateLogCount, state);
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

        // fprintf(stderr, "%d: Server Write, State %ud\n", stateLogCount, state);
        stateLogCount++;
    }

    else if (writeBytes == 0){
        // fprintf(stderr, "%d wrote 0 bytes\n", session->serverConnection.fd);
    }

    else {
        if(errno != EINTR) {

            if(errno == EPIPE) {
                // fprintf(stderr, "Cierre forzoso de parte de server\n");
            }

            socks5_close_session(event);
        }
    }
}

static void socks5_client_read(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->lastInteraction = time(NULL);

    Buffer * buffer = &session->input;
    unsigned state;

    if(!buffer_can_write(buffer)) {
        // fprintf(stderr, "ERROR: Read client socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

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
                // fprintf(stderr, "Unexpected Client Closing %d\n", session->clientConnection.fd);
                socks5_close_session(event);
                return;
            }

            session->clientConnection.state = CLOSING;
        }

        statistics_add_bytes_received(readBytes);

        if(state = selector_state_machine_proccess_read(&session->sessionStateMachine, event), state == FINISH)
            socks5_close_session(event);

        // fprintf(stderr, "%d: Client Read, State %ud\n", stateLogCount, state);
        stateLogCount++;
    }

    else {
        if(errno != EINTR) {
            socks5_close_session(event);
        }
    }
   
}

static void socks5_client_write(SelectorEvent *event){
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->lastInteraction = time(NULL);

    Buffer * buffer = &session->output;
    unsigned state;

    if(!buffer_can_read(buffer)) {
        // fprintf(stderr, "Write client socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

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

        // fprintf(stderr, "%d: Client Write, State %u\n", stateLogCount, state);
        stateLogCount++;
    }
    else if (writeBytes == 0){
        // fprintf(stderr, "%d wrote 0 bytes\n", session->clientConnection.fd);
    }
    else
    {
        if(errno != EINTR) {

            if(errno == EPIPE) {
                // fprintf(stderr, "Cierre forzoso de parte de client\n");
            }

            socks5_close_session(event);
        }
    }
}

static void socks5_dns_read(SelectorEvent *event){
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    DnsHeader *header;

    if(event->fd == session->dnsHeaderContainer->ipv4.dnsConnection.fd) {
        header = &session->dnsHeaderContainer->ipv4;
    }
    else {
        header = &session->dnsHeaderContainer->ipv6;
    }

    Buffer * buffer = &header->buffer;

    if(!buffer_can_write(buffer)) {

        socks5_close_session(event);
        return;
    }

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(buffer, &nbytes);

    readBytes = recv(event->fd, writePtr, nbytes, MSG_NOSIGNAL);

    if(readBytes > 0) {
        buffer_write_adv(buffer, readBytes);
        statistics_add_bytes_received(readBytes);
    }

    if(readBytes == 0 || (readBytes == -1 && errno != EINTR)) {

        // Unexpected DNS Close
        selector_unregister_fd(event->s, event->fd);
    }

    selector_state_machine_proccess_read(&session->sessionStateMachine, event);
}

static void socks5_dns_write(SelectorEvent *event){
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    DnsHeader *header;

    if(event->fd == session->dnsHeaderContainer->ipv4.dnsConnection.fd) {
        header = &session->dnsHeaderContainer->ipv4;
    }
    else {
        header = &session->dnsHeaderContainer->ipv6;
    }

    Buffer * buffer = &header->buffer;

    // ! TODO no me gusta este estado
    if(!buffer_can_read(buffer)) {
        
        if(!header->connected){
            selector_state_machine_proccess_write(&session->sessionStateMachine, event);
            return;
        }
        // Podria no ser necesario
        socks5_close_session(event);
        return;
    }
    
    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if(writeBytes = send(event->fd, readPtr, nbytes, MSG_NOSIGNAL), writeBytes > 0) {
        buffer_read_adv(buffer, writeBytes);

        statistics_add_bytes_sent(writeBytes);

        selector_state_machine_proccess_write(&session->sessionStateMachine, event);

        stateLogCount++;
    }

    else if (writeBytes == 0){
        // fprintf(stderr, "%d wrote 0 bytes\n", session->serverConnection.fd);
    }

    else {
        if(errno != EINTR) {

        // fprintf(stderr, "Write: DNS Connection was unexpectedly closed. Fd: %d. State: %d\n", event->fd, session->sessionStateMachine.current);

        // Unexpected DNS Close
        // header->dnsConnection.state = INVALID;
        selector_unregister_fd(event->s, event->fd);

        selector_state_machine_proccess_write(&session->sessionStateMachine, event);
        }
    }
}

static SessionHandlerP socks5_session_init(void) {

    SessionHandlerP session = calloc(1, sizeof(*session));
    if(session == NULL){
        return NULL;
    }

    uint8_t *inputBuffer = malloc(sessionInputBufferSize*sizeof(*inputBuffer));
    if(inputBuffer == NULL){
        free(session);
        return NULL;
    }
        
    uint8_t *outputBuffer = malloc(sessionOutputBufferSize*sizeof(*outputBuffer));
    if(outputBuffer == NULL){
        free(session);
        free(inputBuffer);
        return NULL;
    }

    buffer_init(&session->input, sessionInputBufferSize, inputBuffer);
    buffer_init(&session->output, sessionOutputBufferSize, outputBuffer);

    build_socks_session_state_machine(&session->sessionStateMachine);

    session->clientInfo.connectedDomain = NULL;
    session->dnsHeaderContainer = NULL;

    session->clientConnection.state = OPEN;
    session->serverConnection.state = INVALID;

    session->lastInteraction = time(NULL);

    statistics_inc_current_connection();

    return session;
}

static void socks5_client_close(SelectorEvent *event){
    
     SessionHandlerP session = (SessionHandlerP) event->data;
    
    if(session->serverConnection.state != INVALID) {
        selector_unregister_fd(event->s, session->serverConnection.fd);
    }

    if(session->dnsHeaderContainer != NULL) {
        
        if(session->dnsHeaderContainer->ipv4.dnsConnection.state != INVALID) {
            selector_unregister_fd(event->s, session->dnsHeaderContainer->ipv4.dnsConnection.fd);
        } 
        else {
            // fprintf(stderr, "DNS was already invalid. Fd: %d. State: %d\n", session->dnsHeaderContainer->ipv4.dnsConnection.fd, session->sessionStateMachine.current);
        }
        
        if(session->dnsHeaderContainer->ipv6.dnsConnection.state != INVALID) {
            selector_unregister_fd(event->s, session->dnsHeaderContainer->ipv6.dnsConnection.fd);
        }
        else {
            // fprintf(stderr, "DNS was already invalid. Fd: %d. State: %d\n", session->dnsHeaderContainer->ipv6.dnsConnection.fd, session->sessionStateMachine.current);
        }

        if(session->dnsHeaderContainer->ipv4.buffer.data != NULL) {
            free(session->dnsHeaderContainer->ipv4.buffer.data);
            session->dnsHeaderContainer->ipv4.buffer.data = NULL;
        }

        if(session->dnsHeaderContainer->ipv4.responseParser.addresses != NULL) {
            free(session->dnsHeaderContainer->ipv4.responseParser.addresses);
            session->dnsHeaderContainer->ipv4.responseParser.addresses = NULL;
        }

        if(session->dnsHeaderContainer->ipv6.buffer.data != NULL) {
            free(session->dnsHeaderContainer->ipv6.buffer.data);
            session->dnsHeaderContainer->ipv6.buffer.data = NULL;
        }

        if(session->dnsHeaderContainer->ipv6.responseParser.addresses != NULL) {
            free(session->dnsHeaderContainer->ipv6.responseParser.addresses);
            session->dnsHeaderContainer->ipv6.responseParser.addresses = NULL;
        }

        free(session->dnsHeaderContainer);
        session->dnsHeaderContainer = NULL;
    }
    else {
    //    fprintf(stderr, "DNSContainer was NULL. Client Fd: %d. State: %d\n", session->clientConnection.fd, session->sessionStateMachine.current);
    }   

    selector_state_machine_close(&session->sessionStateMachine, event);

    if(session->clientInfo.user != NULL) {
        session->clientInfo.user->connectionCount--;

        if(session->clientInfo.user->connectionCount == 0) {
            statistics_dec_current_user_count();
        }

        free(session->clientInfo.connectedDomain);
    } 

    close(session->clientConnection.fd);
    statistics_dec_current_connection();

    free(session->input.data);
    free(session->output.data);
    free(session);
}

static void socks5_server_close(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;
    session->serverConnection.state = INVALID;

    close(event->fd);

    statistics_dec_current_connection();
}

static void socks5_dns_close(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    close(event->fd);
    
    // fprintf(stderr, "DNS closed. Fd: %d. State: %d\n", event->fd, session->sessionStateMachine.current);
    statistics_dec_current_connection();
    
    if(session->dnsHeaderContainer->ipv4.dnsConnection.fd == event->fd) {
        session->dnsHeaderContainer->ipv4.dnsConnection.state = INVALID;
    }
    else {
        session->dnsHeaderContainer->ipv6.dnsConnection.state = INVALID;
    }
    
}

static void socks5_close_session(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;
    
    selector_unregister_fd(event->s, session->clientConnection.fd);
}

void socks5_cleanup_session(SelectorEvent *event) {

    // Socket pasivo
    if(event->data == NULL) {
        return;
    }

    SessionHandlerP session = (SessionHandlerP) event->data;
    // fprintf(stderr, "Try clean of %d. Session: %p.\n", event->fd, (void *) session);
    
    if(event->fd == session->clientConnection.fd && difftime(time(NULL), session->lastInteraction) >= maxSessionInactivity) {
        
        // fprintf(stderr, "Cleaned Up Session of Client Socket %d\n", event->fd);
        selector_unregister_fd(event->s, event->fd);
    }
}
