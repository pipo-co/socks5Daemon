#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include "netutils/netutils.h"
#include "states/stateUtilities/request/requestUtilities.h"

#define DATE_SIZE 30
#define REPLY_SIZE 10

void log_user_access(SessionHandlerP session, ReplyValues rep) {

    char date[DATE_SIZE];
    char clientAddress[SOCKADDR_TO_HUMAN_MIN];
    char serverAddress[DOMAIN_NAME_MAX_LENGTH + 1];

    char *printableServerAddres;
    
    time_t now = time(NULL);
    struct tm *nowTm = localtime(&now);

    strftime(date, DATE_SIZE, "%FT%TZ", nowTm);

    sockaddr_to_human(clientAddress, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *)&session->clientConnection.addr);

    if(session->socksHeader.requestHeader.parser.addressType == SOCKS_5_ADD_TYPE_IP4 || session->socksHeader.requestHeader.parser.addressType == SOCKS_5_ADD_TYPE_IP6) {
        
        // TODO En los casos de error faltaria que se imprima bien la IP
        sockaddr_to_human(serverAddress, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *)&session->serverConnection.addr);
        printableServerAddres = serverAddress;
    }

    //! connectedDomain no deberia ser NULL en este estado.
    else {
        printableServerAddres = session->clientInfo.connectedDomain;
    }

    printf("%s\t%s\tA\t%s\t%s\t%d\n", date, session->clientInfo.user->username, clientAddress, printableServerAddres, rep);
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