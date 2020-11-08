#include "administration.h"
#include "parsers/authRequest/authRequestParser.c"

#define DEFAULT_INPUT_BUFFER_SIZE 512
#define DEFAULT_OUTPUT_BUFFER_SIZE 512
#define AUTH_ACK_SIZE 2




static AdministrationHandlerP admin_session_init(void);
static void administration_read(SelectorEvent *event);
static void administration_write(SelectorEvent *event);
static void auth_arrival(SelectorEvent *event);
static unsigned auth_read(SelectorEvent *event);
static unsigned auth_write(SelectorEvent *event);
static unsigned auth_write_error(SelectorEvent *event);
static void request_arrival(SelectorEvent *event);
static unsigned request_read(SelectorEvent *event);
static void admin_close_session(SelectorEvent *event);
static void administration_close(SelectorEvent *event);


static int sctp_accept_connection(int passiveFd, struct sockaddr *cli_addr, socklen_t *clilen) {

    int fd;

    do {
        fd = accept(passiveFd, cli_addr, clilen);
    } while(fd < 0 && (errno == EINTR));
    
    if(fd < 0 ) {
        perror("Accept new client connection aborted");
    }

    return fd;
}

void administration_passive_accept(SelectorEvent *event){
    
    int fd, in, flags;
    struct sockaddr_in cli_addr;
    struct sctp_sndrcvinfo sndrcvinfo;
    socklen_t clilen = sizeof(cli_addr);
    
    FdHandler adminHandler;
    

    fd = sctp_accept_connection(event->fd, (struct sockaddr *)&cli_addr, &clilen);
    if(fd < 0){
        fprintf(stderr, "Admin session initialization failed: couldn't accept.\n");
        return;
    }

    AdministrationHandlerP adminSession = admin_session_init();
    if(adminSession == NULL) {
        close(fd);
        fprintf(stderr, "Admin session initialization failed: Not enough memory.\n");
        return;
    }

    adminHandler.handle_read = administration_read;
    adminHandler.handle_write = administration_write;
    adminHandler.handle_close = administration_close;
    adminHandler.handle_block = NULL;

    selector_register(event->s, event->fd, &adminHandler, OP_READ, adminSession);
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

static void administration_read(SelectorEvent *event){

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    
    Buffer * bufferInput = &adminSession->input;
    
    if(!buffer_can_write(bufferInput)){
        fprintf(stderr, "ERROR: Read admin socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

        admin_close_session(event);
        return;
    }

    ssize_t readBytes;
    size_t nbytes;
    uint8_t * writePtr = buffer_write_ptr(bufferInput, &nbytes);

    if(readBytes = recv(event->fd, writePtr, nbytes, MSG_NOSIGNAL), readBytes >= 0) {
        buffer_write_adv(bufferInput, readBytes);

        if(readBytes > 0){
            
            switch (adminSession->currentState)
            {
            case ADMIN_AUTH_ARRIVAL:
                auth_arrival(event);

            case ADMIN_AUTHENTICATING:
                if(adminSession->currentState = auth_read(event), adminSession->currentState == ADMIN_AUTH_ACK || adminSession->currentState == ADMIN_AUTH_ERROR){
                    selector_set_interest_event(event, OP_WRITE);
                }
            
            break;
            case ADMIN_METHOD_ARRIVAL:
                admin_method_arrival(event);

            case ADMIN_METHOD:
                if(adminSession->currentState = request_read(event), adminSession->currentState == ADMIN_METHOD_RESPONSE || adminSession->currentState == ADMIN_METHOD_ERROR){
                    selector_set_interest_event(event, OP_WRITE);
                }

            break;
            default:
                break;
            }

        }
        else{
            //TODO ver el destroy de admin_method
            admin_close_session(event);   
        }
    }
    else {
        if(errno != EINTR) {
            perror("Admin Recv failed");
            admin_close_session(event);
        }
    }
}

static void administration_write(SelectorEvent *event){

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;


    Buffer * buffer = &adminSession->output;


    if(!buffer_can_read(buffer)) {
        fprintf(stderr, "Write client socket %d was registered on pselect, but there was no space in buffer\n", event->fd);

        if(adminSession->currentState == ADMIN_FINISH){
           admin_close_session(event);
        }
        return;
    }

    ssize_t writeBytes;
    size_t nbytes;
    uint8_t * readPtr = buffer_read_ptr(buffer, &nbytes);
    
    if(writeBytes = send(event->fd, readPtr, nbytes, MSG_NOSIGNAL), writeBytes > 0){
        buffer_read_adv(buffer, writeBytes);

        switch (adminSession->currentState)
            {
            case ADMIN_AUTH_ACK:
                if( (adminSession->currentState = auth_write(event)), adminSession->currentState == ADMIN_METHOD_ARRIVAL ){
                    selector_set_interest_event(event, OP_READ);
                }

            break;

            case ADMIN_AUTH_ERROR:
                if( (adminSession->currentState = auth_write_error(event)), adminSession->currentState == ADMIN_FINISH ){
                    admin_close_session(event);
                }

            break;

            case ADMIN_METHOD_RESPONSE:
               if( (adminSession->currentState = response_write(event)), adminSession->currentState == ADMIN_METHOD ){
                   selector_set_interest_event(event, OP_READ);
               }

            break;

            case ADMIN_METHOD_ERROR:
                if( (adminSession->currentState = response_write_error(event)), adminSession->currentState == ADMIN_METHOD ){
                    selector_set_interest_event(event, OP_READ);
                }
                
            break;

            default:
                break;
            }
        
    }
    else if (writeBytes == 0){
        fprintf(stderr, "%d wrote 0 bytes\n", event->fd);
    }
    else
    {
        if(errno != EINTR) {

            if(errno == EPIPE) {
                fprintf(stderr, "Cierre forzoso de parte de client\n");
            }

            perror("Client Send failed");
            admin_close_session(event);
        }
    }
}

static void auth_arrival(SelectorEvent *event) {
    
    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    auth_request_parser_init(&adminSession->adminHeader.authHeader.authParser);

    adminSession->adminHeader.authHeader.bytes = 0;

}

static unsigned auth_read(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    AdminAuthHeader * h = &adminSession->adminHeader.authHeader;
    bool errored;

    if(!auth_request_parser_consume(&adminSession->input, &h->authParser, &errored)) {
        return adminSession->currentState;
    }

    if(errored == true) {
        // loggear ( auth_request_parser_error_message(socks5_p->auth_parser.current_state);)
        h->status = AUTH_FAILED;
        return ADMIN_AUTH_ERROR;
    }

    if(h->authParser.version != AUTH_VERSION) {
        //loggear ("AuthRequest: Invalid version!")
        h->status = INVALID_VERSION;
        return ADMIN_AUTH_ERROR;
    }

    adminSession->user = user_handler_get_user_by_username(h->authParser.username);

    // User does not exist, falta preguntar que si no es admin
    if(adminSession->user == NULL ) {
        h->status = AUTH_FAILED;
        return ADMIN_AUTH_ERROR;
    }

    // Password does not match
    if(strcmp(adminSession->user->password, h->authParser.password) != 0) {
        h->status = AUTH_FAILED;
        return ADMIN_AUTH_ERROR;
    }

    h->status = SUCCESS;
    return ADMIN_METHOD_ARRIVAL;
}

static unsigned auth_write(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    
    auth_marshall(&adminSession->output, &adminSession->adminHeader.authHeader.bytes, adminSession->adminHeader.authHeader.status); 

    if(adminSession->adminHeader.authHeader.bytes == AUTH_ACK_SIZE && !buffer_can_read(&adminSession->output)) {
        return ADMIN_METHOD_ARRIVAL;
    }

    
    return adminSession->currentState;

}

static unsigned auth_write_error(SelectorEvent *event) {

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    
    auth_marshall(&adminSession->output, &adminSession->adminHeader.authHeader.bytes, adminSession->adminHeader.authHeader.status); 

    if(adminSession->adminHeader.authHeader.bytes == AUTH_ACK_SIZE && !buffer_can_read(&adminSession->output)) {
        return ADMIN_FINISH;
    }

    
    return adminSession->currentState;

}

static void auth_marshall(Buffer *b, size_t *bytes, AuthCodesStateEnum status) {

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

static void request_arrival(SelectorEvent *event){

    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;

    admin_method_parser_init(&adminSession->adminHeader.requestHeader.requestParser);

    adminSession->adminHeader.requestHeader.bytes = 0;

}

static unsigned request_read(SelectorEvent *event){
    AdministrationHandlerP adminSession = (AdministrationHandlerP) event->data;
    AdminAuthHeader * h = &adminSession->adminHeader.authHeader;
    bool errored;

    if(!auth_request_parser_consume(&adminSession->input, &h->authParser, &errored)) {
        return adminSession->currentState;
    }

    if(errored == true) {
        // loggear ( auth_request_parser_error_message(socks5_p->auth_parser.current_state);)
        return ADMIN_METHOD_ERROR;
    }

    if(h->authParser.version != AUTH_VERSION) {
        //loggear ("AuthRequest: Invalid version!")
        return ADMIN_METHOD_ERROR;
    }

    adminSession->user = user_handler_get_user_by_username(h->authParser.username);

    // User does not exist, falta preguntar que si no es admin
    if(adminSession->user == NULL ) {
        return ADMIN_METHOD_ERROR;
    }

    // Password does not match
    if(strcmp(adminSession->user->password, h->authParser.password) != 0) {
        return ADMIN_METHOD_ERROR;
    }

    return ADMIN_METHOD_ARRIVAL;
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
