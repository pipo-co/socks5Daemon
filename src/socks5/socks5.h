#ifndef SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector.h"
#include "buffer.h"
#include "hello.h"
#include "request.h"
#include "auth.h"

typedef enum {HELLO = 0, INITIAL_RESPONSE, AUTHENTICATION, REQUEST, FINISHED, EXECUTE_COMMAND} Socks5State;

typedef struct
{
    Buffer input;
    Buffer output;
    int fd;
    Socks5State state;
    HelloParser hello_parser;
    RequestParser request_parser;
    AuthHeader auth_header;
    struct fd_handler fd_handler;
    

}Socks5Handler;

typedef Socks5Handler * Socks5HandlerP;

void passive_accept(struct selector_key *key);

void socks5_process_input(Socks5HandlerP socks5_p);

void socks5_process_output(Socks5HandlerP socks5_p);

Socks5Handler * get_socks5_handler();

#endif