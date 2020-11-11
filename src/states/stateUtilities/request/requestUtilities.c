#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include "netutils/netutils.h"
#include "states/stateUtilities/request/requestUtilities.h"
#include "socks5/logger/logger.h"

#define DATE_SIZE 30
#define REPLY_SIZE 10

#define ACCESS_LOG_MAX_SIZE (DATE_SIZE + CREDENTIAL_MAX_SIZE + SOCKADDR_TO_HUMAN_MIN + DOMAIN_NAME_MAX_LENGTH + 5)
#define CREDENTIAL_SPOOFING_LOG_MAX_SIZE (DATE_SIZE + CREDENTIAL_MAX_SIZE + 4 + DOMAIN_NAME_MAX_LENGTH + CREDENTIAL_MAX_SIZE + CREDENTIAL_MAX_SIZE + 5)

// Should be call in requestParser scope
void log_user_access(SessionHandlerP session, ReplyValues rep) {

    char date[DATE_SIZE];
    char clientAddress[SOCKADDR_TO_HUMAN_MIN];
    char serverAddress[SOCKADDR_TO_HUMAN_MIN];
    char serverPort[SOCKADDR_TO_HUMAN_MIN];

    char *printableServerAddress;
    
    time_t now = time(NULL);
    struct tm *nowTm = localtime(&now);

    strftime(date, DATE_SIZE, "%FT%TZ", nowTm);

    sockaddr_to_human(clientAddress, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *)&session->clientConnection.addr);

    if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP4){
        
        struct in_addr * ipv4 = &((struct sockaddr_in *)&session->serverConnection.addr)->sin_addr;
        inet_ntop(AF_INET, ipv4, serverAddress, SOCKADDR_TO_HUMAN_MIN);
        printableServerAddress = serverAddress;
    }
    else if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP6){
        
        struct in6_addr * ipv6 = &((struct sockaddr_in6 *)&session->serverConnection.addr)->sin6_addr;
        inet_ntop(AF_INET6, ipv6, serverAddress, SOCKADDR_TO_HUMAN_MIN);
        printableServerAddress = serverAddress;
    }
    else {
        printableServerAddress = session->clientInfo.connectedDomain;
    }
    
    snprintf(serverPort, SOCKADDR_TO_HUMAN_MIN, "%u", ntohs(session->clientInfo.port));
    
    char printBuffer[ACCESS_LOG_MAX_SIZE];
    int logLen;

    // dateSize (DATE_SIZE) + user (CREDENTIAL_MAX_SIZE) + clientAddress (SOCKADDR_TO_HUMAN_MIN) + printableServerAddress (DOMAIN_NAME_MAX_LENGTH + 1) + rep (1)
    logLen = snprintf(printBuffer, ACCESS_LOG_MAX_SIZE, "%s\t%s\tA\t%s\t%s\t%s\t%d\n", date, session->clientInfo.user->username, clientAddress, printableServerAddress, serverPort,rep);

    if(logLen > ACCESS_LOG_MAX_SIZE) {
        logLen = ACCESS_LOG_MAX_SIZE;
    }

    logger_non_blocking_log(STDOUT_FILENO, printBuffer, logLen);
}

void log_credential_spoofing(SessionHandlerP session) {

    char date[DATE_SIZE];
    char serverAddress[SOCKADDR_TO_HUMAN_MIN];
    char serverPort[SOCKADDR_TO_HUMAN_MIN];

    char *printableServerAddress;

    time_t now = time(NULL);
    struct tm *nowTm = localtime(&now);

    strftime(date, DATE_SIZE, "%FT%TZ", nowTm);

    char* protocol = (session->socksHeader.spoofingHeader.parser.protocol == SPOOF_POP)? "POP3" : "HTTP";

    if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP4){
        
        struct in_addr * ipv4 = &((struct sockaddr_in *)&session->serverConnection.addr)->sin_addr;
        inet_ntop(AF_INET, ipv4, serverAddress, SOCKADDR_TO_HUMAN_MIN);
        printableServerAddress = serverAddress;
    }
    else if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP6){
        
        struct in6_addr * ipv6 = &((struct sockaddr_in6 *)&session->serverConnection.addr)->sin6_addr;
        inet_ntop(AF_INET6, ipv6, serverAddress, SOCKADDR_TO_HUMAN_MIN);
        printableServerAddress = serverAddress;
    }

    else {
        printableServerAddress = session->clientInfo.connectedDomain;
    }

    snprintf(serverPort, SOCKADDR_TO_HUMAN_MIN, "%u", ntohs(session->clientInfo.port));

    char *username = session->socksHeader.spoofingHeader.parser.username;
    char *password = session->socksHeader.spoofingHeader.parser.password;

    char printBuffer[CREDENTIAL_SPOOFING_LOG_MAX_SIZE];
    int logLen;

    // dateSize (DATE_SIZE) + user (CREDENTIAL_MAX_SIZE) + protocol (4) + printableServerAddress (DOMAIN_NAME_MAX_LENGTH + 1) + username (CREDENTIAL_MAX_SIZE) + password (CREDENTIAL_MAX_SIZE)
    logLen = snprintf(printBuffer, CREDENTIAL_SPOOFING_LOG_MAX_SIZE, "%s\t%s\tP\t%s\t%s\t%s\t%s\t%s\n", date, session->clientInfo.user->username, protocol, printableServerAddress, serverPort,username, password);

    if(logLen > CREDENTIAL_SPOOFING_LOG_MAX_SIZE) {
        logLen = CREDENTIAL_SPOOFING_LOG_MAX_SIZE;
    }

    logger_non_blocking_log(STDOUT_FILENO, printBuffer, logLen);
}

bool request_marshall(Buffer *b, size_t *bytes, ReplyValues rep) {

    while(*bytes < REPLY_SIZE && buffer_can_write(b)){
        if(*bytes == 0){
            buffer_write(b, SOCKS_VERSION);
        }
        else if(*bytes == 1){
            buffer_write(b, rep);
        }
        else if (*bytes == 2){
            buffer_write(b, RSV);
        }
        else if (*bytes == 3){
            buffer_write(b, ATYP);
        }
        else {
            buffer_write(b, 0);
        }
        (*bytes)++;
    }

    return *bytes >= REPLY_SIZE;
}

ReplyValues request_get_reply_value_from_errno(int error) {
    
    if(error == ENETUNREACH){
        return NETWORK_UNREACHABLE;
    }

    else if(error == EHOSTUNREACH) {
        return HOST_UNREACHABLE;
    }

    else if(error == ECONNREFUSED) {
        return CONNECTION_REFUSED;
    }

    return GENERAL_SOCKS_SERVER_FAILURE;
}