#ifndef SOCKS5_SESSION_DEFINITION_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define SOCKS5_SESSION_DEFINITION_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <arpa/inet.h>

#include "selector/selector.h"
#include "buffer/buffer.h"
#include "stateMachine/selectorStateMachine.h"

#include "parsers/hello/helloParser.h"
#include "parsers/authRequest/authRequestParser.h"
#include "parsers/request/requestParser.h"

typedef enum SessionState {
    HELLO = 0, 
    HELLO_ERROR, 
    AUTH_METHOD_ANNOUNCEMENT,
    AUTH_REQUEST,
    AUTH_ERROR,
    AUTH_SUCCESSFUL,
    REQUEST,
    REQUEST_ERROR,
    IP_CONNECT,
    // GENERATE_DNS_QUERY,
    REQUEST_SUCCESSFUL,
    // FORWARDING,
    FINISH,
} SessionState;

typedef struct Connection {
    int fd;
    struct sockaddr addr;
    bool closed;
} Connection;

// Esto seguramente no vaya aca
typedef struct ClientInfo {
  uint8_t authMethod;
  uint32_t identifier;
} ClientInfo;

typedef struct HelloHeader{
    HelloParser parser;
    size_t bytes;
} HelloHeader;

typedef struct AuthRequestHeader{
    AuthRequestParser parser;
    size_t bytes;
} AuthRequestHeader;

typedef struct RequestHeader{
    RequestParser parser;
    size_t bytes;
    uint8_t rep;
} RequestHeader;

typedef union SocksHeaders{
    HelloHeader helloHeader;    
    AuthRequestHeader authRequestHeader;
    RequestHeader requestHeader;   
} SocksHeaders;

typedef struct SessionHandler {
    Buffer input;
    Buffer output;

    SelectorStateMachine sessionStateMachine;

    Connection clientConnection;
    Connection serverConnection;
    Connection dnsConnection;

    ClientInfo clientInfo;
    
    SocksHeaders socksHeader;
    
} SessionHandler;

typedef SessionHandler * SessionHandlerP;
#endif