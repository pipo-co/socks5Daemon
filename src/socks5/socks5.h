#ifndef SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define SOCKS5_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include "selector.h"
#include "buffer.h"
#include "../states/hello/hello.h"
#include "../states/authRequest/authRequest.h"
#include "../states/request/request.h"
#include "auth.h"
#include "connect.h"
#include "stateMachine.h"
#define BUFFSIZE 512

typedef enum Socks5State {
    HELLO = 0, HELLO_ERROR, 
    AUTH_METHOD_ANNOUNCEMENT, AUTH_REQUEST, AUTH_ERROR, AUTH_SUCCESSFUL,
    REQUEST, REQUEST_ERROR,
    IP_CONNECT,
    GENERATE_DNS_QUERY,
    FORWARDING,
    FINNISH} Socks5State;

typedef struct ConnectionInfo{
    int fd;
    struct sockaddr addr;
}ConnectionInfo;

// Esto seguramente no vaya aca
typedef struct ClientInfo{
  uint8_t authMethod;
  uint32_t identifier;
}ClientInfo;

union SocksHeaders{
    struct HelloHeader helloHeader;    
    struct AuthRequestHeader authRequestHeader;
    struct RequestHeader requestHeader;   
};
typedef struct Socks5Handler
{
    Buffer input;
    Buffer output;

    uint8_t rawBufferInput[BUFFSIZE];
    uint8_t rawBufferOutput[BUFFSIZE];

    struct fd_handler fd_handler;

    struct StateMachine stm;

    struct ConnectionInfo clientConnection;
    struct ConnectionInfo serverConnection;

    struct ClientInfo clientInfo;
    
    union SocksHeaders socksHeader;
    
}Socks5Handler;

typedef Socks5Handler * Socks5HandlerP;

void socks5_passive_accept(struct selector_key *key);

void socks5_register_server(fd_selector s, Socks5HandlerP socks5_p);

Socks5Handler * get_socks5_handler();

#endif