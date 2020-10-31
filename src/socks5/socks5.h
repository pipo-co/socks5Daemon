#ifndef SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector.h"
#include "buffer.h"
#include "hello.h"
#include "request.h"
#include "auth.h"
#include "connect.h"

typedef enum Socks5State {HELLO = 0, INITIAL_RESPONSE, AUTHENTICATION, REQUEST, EXECUTE_COMMAND, REPLY, FORWARDING} Socks5State;

typedef struct Socks5Handler
{
    Buffer input;
    Buffer output;
    int fd;
    Socks5State state;
    HelloParser hello_parser;
    RequestParser request_parser;
    AuthHeader auth_header;
    ConnectHeader connect_header;
    struct fd_handler fd_handler;
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