#include "administration.h"
#include "parsers/authRequest/authRequestParser.h"
#include "parsers/adminRequestParser/adminRequestParser.h"

#define DEFAULT_INPUT_BUFFER_SIZE 512
#define DEFAULT_OUTPUT_BUFFER_SIZE 512
#define AUTH_ACK_SIZE 2

static AdministrationHandlerP admin_session_init(void);
static void admin_on_read_handler(SelectorEvent *event);
static void admin_on_write_handler(SelectorEvent *event);
static void admin_auth_arrival(SelectorEvent *event);
static AdminStateEnum admin_auth_read(SelectorEvent *event);
static AdminStateEnum auth_write(SelectorEvent *event);
static AdminStateEnum auth_write_error(SelectorEvent *event);
static void admin_auth_marshall(Buffer *b, size_t *bytes, AuthCodesStateEnum status);
static void admin_request_arrival(SelectorEvent *event);
static AdminStateEnum admin_request_read(SelectorEvent *event);
static AdminStateEnum admin_response_write(SelectorEvent *event);
static void admin_close_session(SelectorEvent *event);
static void administration_close(SelectorEvent *event);
static void admin_passive_accept_util(SelectorEvent *event, struct sockaddr *cli_addr, socklen_t *clilen);
static void admin_post_read_handler(SelectorEvent *event);
static void admin_post_write_handler(SelectorEvent *event);


static int sctp_accept_connection(int passiveFd, struct sockaddr *cli_addr, socklen_t *clilen) {

    int fd;

    do {
        fd = accept(passiveFd, cli_addr, clilen);
    } while(fd < 0 && (errno == EINTR));

    return fd;
}

void admin_passive_accept_ipv4(SelectorEvent *event) {
    
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    admin_passive_accept_util(event, (struct sockaddr *)&cli_addr, &clilen);
}

void admin_passive_accept_ipv6(SelectorEvent *event) {

    struct sockaddr_in6 cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    
    admin_passive_accept_util(event, (struct sockaddr *) &cli_addr, &clilen);
}

static void admin_passive_accept_util(SelectorEvent *event, struct sockaddr *cli_addr, socklen_t *clilen) {

    int fd;
    FdHandler adminHandler;

    fd = sctp_accept_connection(event->fd, cli_addr, clilen);
    if(fd < 0){
        return;
    }

    AdministrationHandlerP adminSession = admin_session_init();
    if(adminSession == NULL) {
        close(fd);
        return;
    }

    adminHandler.handle_read = admin_on_read_handler;
    adminHandler.handle_write = admin_on_write_handler;
    adminHandler.handle_close = administration_close;
    adminHandler.handle_block = NULL;

    selector_register(event->s, fd, &adminHandler, OP_READ, adminSession);
}

static AdministrationHandlerP admin_session_init(void) {

    AdministrationHandlerP adminSession = calloc(1, sizeof(*adminSession));
    if(adminSession == NULL){
        return NULL;
    }

    uint8_t *inputBuffer = malloc(DEFAULT_INPUT_BUFFER_SIZE*sizeof(*inputBuffer));
    if(inputBuffer == NULL){
        free(adminSession);
        return NULL;
    }
        
    uint8_t *outputBuffer = malloc(DEFAULT_OUTPUT_BUFFER_SIZE*sizeof(*outputBuffer));
    if(outputBuffer == NULL){
        free(adminSession);
        free(inputBuffer);
        return NULL;
    }
    
    adminSession->currentState = ADMIN_AUTH_ARRIVAL;
    buffer_init(&adminSession->input, DEFAULT_INPUT_BUFFER_SIZE, inputBuffer);
    buffer_init(&adminSession->output, DEFAULT_OUTPUT_BUFFER_SIZE, outputBuffer);

    return adminSession;
}

static void admin_on_read_handler(SelectorEvent *event){

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    
    Buffer * bufferInput = &adminSession->input;
    
    // Error
    if(!buffer_can_write(bufferInput)){

        admin_close_session(event);
        return;
    }

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(bufferInput, &nbytes);

    if(readBytes = recv(event->fd, writePtr, nbytes, MSG_NOSIGNAL), readBytes > 0) {
        buffer_write_adv(bufferInput, readBytes);

        admin_post_read_handler(event);
    }

    // Connection Was Closed
    else if(readBytes == 0){      
        //TODO ver el destroy de admin_method
        admin_close_session(event);  
    }
        
    else if(errno != EINTR) {
        admin_close_session(event);
    }
}

static void admin_on_write_handler(SelectorEvent *event){

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    Buffer * buffer = &adminSession->output;

    // Error
    if(!buffer_can_read(buffer)) {

        admin_close_session(event);
        return;
    }

    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if(writeBytes = send(event->fd, readPtr, nbytes, MSG_NOSIGNAL), writeBytes > 0){
        buffer_read_adv(buffer, writeBytes);

        admin_post_write_handler(event);
        
    }

    // Client Closed Connection Unexpectedly
    else if(writeBytes < 0 && errno != EINTR) {
        admin_close_session(event);
    }
}

static void admin_post_read_handler(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
        
    switch (adminSession->currentState) {

        case ADMIN_AUTH_ARRIVAL:
            admin_auth_arrival(event);

        case ADMIN_AUTHENTICATING:
            if(adminSession->currentState = admin_auth_read(event), adminSession->currentState == ADMIN_AUTH_ACK || adminSession->currentState == ADMIN_AUTH_ERROR){
                selector_set_interest_event(event, OP_WRITE);
            }

        break;

        case ADMIN_METHOD_ARRIVAL:
            admin_request_arrival(event);

        case ADMIN_METHOD:
            if(adminSession->currentState = admin_request_read(event), adminSession->currentState == ADMIN_METHOD_RESPONSE){
                selector_set_interest_event(event, OP_WRITE);
            }

        break;
    }
}

static void admin_post_write_handler(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    switch (adminSession->currentState) {

        case ADMIN_AUTH_ACK:
            if(adminSession->currentState = auth_write(event), adminSession->currentState == ADMIN_METHOD_ARRIVAL){
                selector_set_interest_event(event, OP_READ);
            }

        break;

        case ADMIN_AUTH_ERROR:
            if(adminSession->currentState = auth_write_error(event), adminSession->currentState == ADMIN_FINISH){
                admin_close_session(event);
            }

        break;

        case ADMIN_METHOD_RESPONSE:
            if(adminSession->currentState = admin_response_write(event), adminSession->currentState == ADMIN_METHOD){
                selector_set_interest_event(event, OP_READ);
            }

        break;
    }
}

static void admin_auth_arrival(SelectorEvent *event) {
    
    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    auth_request_parser_init(&adminSession->adminHeader.authHeader.authParser);

    adminSession->adminHeader.authHeader.bytes = 0;
}

static AdminStateEnum admin_auth_read(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    AdminAuthHeader * h = &adminSession->adminHeader.authHeader;
    bool errored;

    if(!auth_request_parser_consume(&adminSession->input, &h->authParser, &errored)) {
        return adminSession->currentState;
    }

    if(errored == true) {

        if(h->authParser.errorType == AUTH_REQUEST_INVALID_VERSION) {
            h->status = INVALID_VERSION;
        }
        else {
            h->status = AUTH_FAILED;
        }

        return ADMIN_AUTH_ERROR;
    }

    adminSession->user = user_handler_get_user_by_username(h->authParser.username);

    // User does not exist, falta preguntar que si no es admin
    if(adminSession->user == NULL) {
        h->status = AUTH_FAILED;
        return ADMIN_AUTH_ERROR;
    }

    // Password does not match
    if(strcmp(adminSession->user->password, h->authParser.password) != 0 || !adminSession->user->admin) {
        h->status = AUTH_FAILED;
        return ADMIN_AUTH_ERROR;
    }

    h->status = SUCCESS;
    return ADMIN_METHOD_ARRIVAL;
}

static AdminStateEnum auth_write(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    
    admin_auth_marshall(&adminSession->output, &adminSession->adminHeader.authHeader.bytes, adminSession->adminHeader.authHeader.status); 

    if(adminSession->adminHeader.authHeader.bytes == AUTH_ACK_SIZE && !buffer_can_read(&adminSession->output)) {
        return ADMIN_METHOD_ARRIVAL;
    }

    return adminSession->currentState;
}

static AdminStateEnum auth_write_error(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    
    admin_auth_marshall(&adminSession->output, &adminSession->adminHeader.authHeader.bytes, adminSession->adminHeader.authHeader.status); 

    if(adminSession->adminHeader.authHeader.bytes == AUTH_ACK_SIZE && !buffer_can_read(&adminSession->output)) {
        return ADMIN_FINISH;
    }

    return adminSession->currentState;
}

static void admin_auth_marshall(Buffer *b, size_t *bytes, AuthCodesStateEnum status) {

    while(*bytes < AUTH_ACK_SIZE && buffer_can_write(b)){

        if(*bytes == 0){
            buffer_write(b, AUTH_VERSION);
        }
        if(*bytes == 1){
            buffer_write(b, status);
        }
        (*bytes)++;
    }
}

static void admin_request_arrival(SelectorEvent *event){

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    admin_request_parser_init(&adminSession->adminHeader.requestHeader.requestParser);

}

static AdminStateEnum admin_request_read(SelectorEvent *event){
    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    AdminRequestHeader * h = &adminSession->adminHeader.requestHeader;
    bool errored;

    if(!admin_request_parser_consume(&h->requestParser, &adminSession->input, &errored)) {
        return adminSession->currentState;
    }

    h->requestParser.request_handler(h->requestParser.type, h->requestParser.command, &h->requestParser.args, &h->responseBuilder);
    return ADMIN_METHOD_RESPONSE;
}

static AdminStateEnum admin_response_write(SelectorEvent *event){
    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    AdminResponseBuilderContainer * b = &adminSession->adminHeader.requestHeader.responseBuilder; 

    if(b->admin_response_builder(b, &adminSession->output) && !buffer_can_read(&adminSession->output)){
        return ADMIN_METHOD;
    }

    return adminSession->currentState;
}

static void admin_close_session(SelectorEvent *event) {
    selector_unregister_fd(event->s, event->fd);
}

static void administration_close(SelectorEvent *event){
    
    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    close(event->fd);

    free(adminSession->input.data);
    free(adminSession->output.data);
    free(adminSession);
}
