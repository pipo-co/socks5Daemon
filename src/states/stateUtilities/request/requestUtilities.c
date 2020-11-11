#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#include "netutils/netutils.h"
#include "states/stateUtilities/request/requestUtilities.h"
#include "socks5/logger/logger.h"


#define ACCESS_LOG_MAX_SIZE (RU_DATE_SIZE + RU_CREDENTIAL_MAX_SIZE + SOCKADDR_TO_HUMAN_MIN + RU_DOMAIN_NAME_MAX_LENGTH + 5)
#define CREDENTIAL_SPOOFING_LOG_MAX_SIZE (RU_DATE_SIZE + RU_CREDENTIAL_MAX_SIZE + 4 + RU_DOMAIN_NAME_MAX_LENGTH + RU_CREDENTIAL_MAX_SIZE + RU_CREDENTIAL_MAX_SIZE + 5)

// TODO: Cuando imprime domain name tambien tiene que imprimir puerto (ambos logs)
void log_user_access(SessionHandlerP session, ReplyValues rep) {

    char date[RU_DATE_SIZE];
    char clientAddress[SOCKADDR_TO_HUMAN_MIN];
    char serverAddress[SOCKADDR_TO_HUMAN_MIN];

    char *printableServerAddress;
    
    time_t now = time(NULL);
    struct tm *nowTm = localtime(&now);

    strftime(date, RU_DATE_SIZE, "%FT%TZ", nowTm);

    sockaddr_to_human(clientAddress, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *)&session->clientConnection.addr);

    if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP4 || session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP6) {
        
        // TODO En los casos de error faltaria que se imprima bien la IP
        sockaddr_to_human(serverAddress, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *)&session->serverConnection.addr);
        printableServerAddress = serverAddress;
    }

    //! connectedDomain no deberia ser NULL en este estado.
    else {
        printableServerAddress = session->clientInfo.connectedDomain;
    }

    char printBuffer[ACCESS_LOG_MAX_SIZE];
    int logLen;

    // dateSize (DATE_SIZE) + user (CREDENTIAL_MAX_SIZE) + clientAddress (SOCKADDR_TO_HUMAN_MIN) + printableServerAddress (DOMAIN_NAME_MAX_LENGTH + 1) + rep (1)
    logLen = snprintf(printBuffer, ACCESS_LOG_MAX_SIZE, "%s\t%s\tA\t%s\t%s\t%d\n", date, session->clientInfo.user->username, clientAddress, printableServerAddress, rep);

    if(logLen > ACCESS_LOG_MAX_SIZE) {
        logLen = ACCESS_LOG_MAX_SIZE;
    }

    logger_non_blocking_log(STDOUT_FILENO, printBuffer, logLen);
}

void log_credential_spoofing(SessionHandlerP session) {

    char date[RU_DATE_SIZE];
    char serverAddress[SOCKADDR_TO_HUMAN_MIN];

    char *printableServerAddress;

    time_t now = time(NULL);
    struct tm *nowTm = localtime(&now);

    strftime(date, RU_DATE_SIZE, "%FT%TZ", nowTm);

    char* protocol = (session->socksHeader.spoofingHeader.parser.protocol == SPOOF_POP)? "POP3" : "HTTP";

    if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP4 || session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP6) {
        
        sockaddr_to_human(serverAddress, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *)&session->serverConnection.addr);
        printableServerAddress = serverAddress;
    }

    //! connectedDomain no deberia ser NULL en este estado.
    else {
        printableServerAddress = session->clientInfo.connectedDomain;
    }

    char *username = session->socksHeader.spoofingHeader.parser.username;
    char *password = session->socksHeader.spoofingHeader.parser.password;

    char printBuffer[CREDENTIAL_SPOOFING_LOG_MAX_SIZE];
    int logLen;

    // dateSize (RU_DATE_SIZE) + user (RU_CREDENTIAL_MAX_SIZE) + protocol (4) + printableServerAddress (RU_DOMAIN_NAME_MAX_LENGTH + 1) + username (RU_CREDENTIAL_MAX_SIZE) + password (RU_CREDENTIAL_MAX_SIZE)
    logLen = snprintf(printBuffer, CREDENTIAL_SPOOFING_LOG_MAX_SIZE, "%s\t%s\tP\t%s\t%s\t%s\t%s\n", date, session->clientInfo.user->username, protocol, printableServerAddress, username, password);

    if(logLen > CREDENTIAL_SPOOFING_LOG_MAX_SIZE) {
        logLen = CREDENTIAL_SPOOFING_LOG_MAX_SIZE;
    }

    logger_non_blocking_log(STDOUT_FILENO, printBuffer, logLen);
}

bool request_marshall(Buffer *b, size_t *bytes, ReplyValues rep) {

    while(*bytes < RU_REPLY_SIZE && buffer_can_write(b)){
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

    return *bytes >= RU_REPLY_SIZE;
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