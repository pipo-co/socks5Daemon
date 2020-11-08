#ifndef ADMINISTRATION_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define ADMINISTRATION_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "argsHandler/argsHandler.h"
#include "selector/selector.h"
#include "netutils/netutils.h"
#include "socks5/socks5.h"

#define QUERY_BUFFER 128

typedef enum AdminStateEnum {
    ADMIN_AUTH_ARRIVAL,
    ADMIN_AUTHENTICATING,
    ADMIN_AUTH_ACK,
    ADMIN_METHOD_ARRIVAL,
    ADMIN_METHOD,
    ADMIN_METHOD_RESPONSE,
    ADMIN_FINISH,
    ADMIN_AUTH_ERROR,
    ADMIN_METHOD_ERROR
 } AdminStateEnum;

typedef enum AuthCodesStateEnum {
    SUCCESS,
    AUTH_FAILED,
    INVALID_VERSION
} AuthCodesStateEnum;

typedef struct AdminAuthHeader {
    AuthRequestParser authParser;
    size_t bytes;
    AuthCodesStateEnum status;

} AdminAuthHeader;

typedef struct AdminRequestHeader{
    AdminRequestParser requestParser;
    size_t bytes;

} RequestHeader;

typedef union AdminHeaders{
    AdminAuthHeader authHeader;    
    AdminRequestParser requestHeader;
} AdminHeaders;

typedef struct AdministrationHandler {
    Buffer input;
    Buffer output;
    
    AdminHeaders adminHeader;

    AdminStateEnum currentState;

    UserInfoP user;

    
} AdministrationHandler;

typedef AdministrationHandler * AdministrationHandlerP;

void admin_passive_accept_ipv4(SelectorEvent *event);

void admin_passive_accept_ipv6(SelectorEvent *event);

#endif