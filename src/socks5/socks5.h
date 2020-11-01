#ifndef SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector.h"
#include "buffer.h"
#include "hello.h"
#include "request.h"
#include "auth.h"
#include "connect.h"
#include "stm.h"
#include "authRequest.h"

typedef enum Socks5State {
    HELLO = 0, HELLO_ERROR, 
    AUTH_METHOD_ANNOUNCEMENT, AUTH_REQUEST, AUTH_ERROR, AUTH_SUCCESSFUL,
    REQUEST, REQUEST_ERROR,
    IP_CONNECT,
    GENERATE_DNS_QUERY,
    FORWARDING} Socks5State;

typedef struct Socks5Handler
{
    Buffer input;
    Buffer output;

    Socks5State state;

    struct state_machine stm;

    int fd;
    
    struct fd_handler fd_handler;
    
    HelloParser hello_parser;
    uint8_t authMethod;
    uint8_t bytesSent;
    AuthRequestParser authRequestParser;
    uint8_t bytesSentAuth;
    RequestParser request_parser;
    int sock;
    uint8_t rep;
    uint8_t bytesSentReq;
    
}Socks5Handler;

typedef struct ServerHandler
{
    Buffer input;
    Buffer output;
    int fd;
    struct fd_handler fd_handler;
    void (*process_information)(struct ServerHandler * s, uint8_t * buffer, size_t size);
    void *data;

}ServerHandler;


typedef Socks5Handler * Socks5HandlerP;
typedef ServerHandler * ServerHandlerP;

void passive_accept(struct selector_key *key);

// void socks5_process_input(Socks5HandlerP socks5_p, fd_selector selector);

// void socks5_process_output(Socks5HandlerP socks5_p, fd_selector selector);

// void forward_server_data_read(struct selector_key *key);

// void forward_server_data_write(struct selector_key *key);

Socks5Handler * get_socks5_handler();

#endif