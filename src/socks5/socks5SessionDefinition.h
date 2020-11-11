#ifndef SOCKS5_SESSION_DEFINITION_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define SOCKS5_SESSION_DEFINITION_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>

#include "selector/selector.h"
#include "buffer/buffer.h"
#include "stateMachine/selectorStateMachine.h"
#include "userHandler/userHandler.h"

#include "parsers/hello/helloParser.h"
#include "parsers/authRequest/authRequestParser.h"
#include "parsers/dns/dnsParser.h"
#include "parsers/dns/httpDnsParser.h"
#include "parsers/request/requestParser.h"
#include "parsers/spoofing/spoofingParser.h"

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
    GENERATE_DNS_QUERY,
    RESPONSE_DNS,
    DNS_CONNECT,
    REQUEST_SUCCESSFUL,
    FORWARDING,
    FLUSH_CLOSER,
    FLUSH_CLOSY,
    FINISH,
} SessionState;

typedef enum SocketState {
    INVALID,
    OPEN,
    CLOSING,
    CLOSED,
} SocketState;

typedef struct Connection {
    int fd;
    struct sockaddr_storage addr;
    SocketState state;
} Connection;

typedef struct ClientInfo {
  uint8_t authMethod;
  Socks5AddressTypes addressTypeSelected;
  UserInfoP user;
  in_port_t port;
  char * connectedDomain;
} ClientInfo;

typedef struct HelloHeader {
    HelloParser parser;
    size_t bytes;
} HelloHeader;

typedef struct AuthRequestHeader {
    AuthRequestParser parser;
    size_t bytes;
} AuthRequestHeader;

typedef struct DnsHeader {
    Connection dnsConnection;
    Buffer buffer;
    HttpDnsParser httpParser;
    ResponseDnsParser responseParser;
    size_t bytes;
    bool connected;
} DnsHeader;

typedef struct DnsHeaderContainer {
    DnsHeader ipv4;
    DnsHeader ipv6;
}DnsHeaderContainer;

typedef struct RequestHeader {
    RequestParser parser;
    size_t bytes;
    ReplyValues rep;
} RequestHeader;

typedef struct SpoofingHeader {
    SpoofingParser parser;
    size_t bytesRead;
    bool spoofingEnabled;
} SpoofingHeader;

typedef union SocksHeaders {
    HelloHeader helloHeader;    
    AuthRequestHeader authRequestHeader;
    RequestHeader requestHeader;
    SpoofingHeader spoofingHeader;
} SocksHeaders;

typedef struct SessionHandler {
    Buffer input;
    Buffer output;

    SelectorStateMachine sessionStateMachine;

    Connection clientConnection;
    Connection serverConnection;

    ClientInfo clientInfo;

    DnsHeaderContainer *dnsHeaderContainer;
    
    SocksHeaders socksHeader;

    time_t lastInteraction;
    
} SessionHandler;

typedef SessionHandler * SessionHandlerP;
#endif