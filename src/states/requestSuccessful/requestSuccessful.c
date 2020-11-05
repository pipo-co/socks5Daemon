#include "requestSuccessful.h"

#include <time.h>
#include <stdio.h>

#include "netutils/netutils.h"

#define REPLY_SIZE 10

static void request_marshall(Buffer *b, size_t *bytes);
static void request_successful_on_arrival(SelectorEvent *event);
static unsigned request_successful_on_write(SelectorEvent *event);
static void log_user_access(SessionHandlerP session);

static void request_successful_on_arrival(SelectorEvent *event) {
    
    SessionHandlerP session = (SessionHandlerP) event->data;

    session->socksHeader.requestHeader.bytes = 0;

    request_marshall(&session->output, &session->socksHeader.requestHeader.bytes);  

    selector_set_interest(event->s, session->clientConnection.fd, OP_WRITE);
    selector_set_interest(event->s, session->serverConnection.fd, OP_NOOP);
}

static unsigned request_successful_on_write(SelectorEvent *event) {

    SessionHandlerP session = (SessionHandlerP) event->data;

    if(session->socksHeader.requestHeader.bytes == REPLY_SIZE && !buffer_can_read(&session->output)) {

        log_user_access(session);

        return FORWARDING;
    }

    request_marshall(&session->output, &session->socksHeader.requestHeader.bytes); 

    return session->sessionStateMachine.current;
}

static void request_marshall(Buffer *b, size_t *bytes) {

        while(*bytes < REPLY_SIZE && buffer_can_write(b)){
            if(*bytes == 0){
                buffer_write(b, SOCKS_VERSION);
            }
            else if(*bytes == 1){
                buffer_write(b, RESPONSE_SUCCESS_MESSAGE);
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
    }

static void log_user_access(SessionHandlerP session) {

    char date[30];
    char clientAddress[SOCKADDR_TO_HUMAN_MIN];
    char serverAddress[DOMAIN_NAME_MAX_LENGTH + 1];

    char *printableServerAddres;
    
    time_t now = time(NULL);
    struct tm *nowTm = localtime(&now);

    strftime(date, 30, "%FT%TZ", nowTm);

    sockaddr_to_human(clientAddress, SOCKADDR_TO_HUMAN_MIN, &session->clientConnection.addr);

    if(session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP4 || session->clientInfo.addressTypeSelected == SOCKS_5_ADD_TYPE_IP6) {
        sockaddr_to_human(serverAddress, SOCKADDR_TO_HUMAN_MIN, &session->serverConnection.addr);
        printableServerAddres = serverAddress;
    }

    // Domain Name
    else {
        printableServerAddres = session->serverConnection.domainName;
    }

    int status = 0; // TODO: ???

    printf("%s\t%s\tA\t%s\t%s\t%d\n", date, session->clientInfo.user->username, clientAddress, printableServerAddres, status);
}

SelectorStateDefinition request_successful_state_definition_supplier(void) {

    SelectorStateDefinition stateDefinition = {

        .state = REQUEST_SUCCESSFUL,
        .on_arrival = request_successful_on_arrival,
        .on_read = NULL,
        .on_write = request_successful_on_write,
        .on_block_ready = NULL,
        .on_departure = NULL,
    };

    return stateDefinition;
}