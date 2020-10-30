#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "socks5.h"

#define ERROR(msg) perror(msg);

enum SocksSizeConstants {
  MAX_CONNECTIONS = 1024,
  BUFSIZE = 512,
  MAX_METHODS = 255
};

typedef struct{
    Socks5Handler   handler;
    uint8_t         asigned;
} Socks5HandlerHeader;

Socks5HandlerHeader connections[MAX_CONNECTIONS];

static void socks5_client_input(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    printf("buffer_can_write %d\n",!buffer_can_write(&socks5_p->input));
    if(!buffer_can_write(&socks5_p->input))
        return;
    
    ssize_t read_bytes;
    size_t nbytes;
    uint8_t * inputBuffer = buffer_write_ptr(&socks5_p->input, &nbytes);

    if((read_bytes = read(key->fd, inputBuffer, nbytes)) > 0){
        buffer_write_adv(&socks5_p->input, read_bytes);
        socks5_process_input(socks5_p);
    } else if (read_bytes == 0) {
        //Cerro la conexion
    }
    else
        ERROR("Socks client input: error reading")
}

static void socks5_client_output(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    socks5_process_output(socks5_p);

   // printf("about to can read\n");
    if(!buffer_can_read(&socks5_p->output))
        return;

    ssize_t write_bytes;
    size_t nbytes;
    uint8_t * outputBuffer = buffer_read_ptr(&socks5_p->output, &nbytes);
    printf("about to write\n");
    if((write_bytes = write(key->fd, outputBuffer, nbytes)) > 0){
        buffer_read_adv(&socks5_p->output, write_bytes);
    } else if (write_bytes == 0) {
        //Cerro la conexion
    }
    else
        ERROR("Socks client input: error reading")
    
}

void socks5_process_input(Socks5HandlerP socks5_p) {
    printf("socks5_p->state %d buffer_can_read %d\n", socks5_p->state, buffer_can_read(&socks5_p->input));
    bool errored;
    //TODO preguntar por condicion de salida del proccess input
    while(buffer_can_read(&socks5_p->input)){
        switch (socks5_p->state){
        case HELLO:
            hello_parser_consume(&socks5_p->input, &socks5_p->hello_parser, &errored);
            if(hello_is_done(socks5_p->hello_parser.current_state, &errored)){
                socks5_p->state = INITIAL_RESPONSE;
                printf("hello is done\n");
            }
            break;
        case AUTHENTICATION:
            printf("authenticating\n");
            // auth_parser_consume(&socks5_p->input, &socks5_p->hello_parser, &errored);
            // if(auth_is_done(socks5_p->hello_parser.current_state, &errored)){
            //     socks5_p->state = AUTHENTICATION;
            //     printf("hello is done\n");
            // }
            socks5_p->state = REQUEST;
            break;
        case REQUEST:
            request_parser_consume(&socks5_p->input, &socks5_p->request_parser, &errored);
            if(request_is_done(socks5_p->request_parser.currentState, &errored)){
                socks5_p->state = EXECUTE_COMMAND;
                printf("request is done\n");
            }
            break;
        case EXECUTE_COMMAND:
            connectHeaderInit(&socks5_p->connect_header, socks5_p->request_parser.addressType, &socks5_p->request_parser.address,socks5_p->request_parser.addressLength, &socks5_p->request_parser.port);
            if(socks5_p->request_parser.addressType == REQUEST_ADD_TYPE_IP4){
                if(establishConnectionIp4(&socks5_p->connect_header) == -1)
                    return;
                printf("Established connection on %s port %s\n", socks5_p->connect_header.dst_addr, socks5_p->connect_header.port);
                socks5_p->state = REPLY;
                return;
            }
        case FINISHED:
            printf("connecting to socket\n");   
        default:
            return;
        }
    }
}
void socks5_process_output(Socks5HandlerP socks5_p) {
    //printf("socks5_p->state %d \n", socks5_p->state);

    //TODO preguntar por condicion de salida del proccess input
    while(buffer_can_write(&socks5_p->output)){
        switch (socks5_p->state){
            case INITIAL_RESPONSE:
            printf("INITIAL RESPONSE\n");
            socks5_p->auth_header.auth_method = chooseAuthMethod(&socks5_p->hello_parser);
            printf("selected method: %d\n", socks5_p->auth_header.auth_method);
            if(socks5_p->auth_header.auth_method < 0){
                ERROR("Authentication method accept: invalid method!\n");
                return;
            }
            if(hello_marshall(&socks5_p->output, socks5_p->auth_header.auth_method) == -1){
                ERROR("initial response: not enough space!\n");
            }
            else{
                socks5_p->state = AUTHENTICATION;
                return;
            }
            break;
            case REPLY:
                printf("REPLYING\n");
                if(request_marshall(&socks5_p->output,&socks5_p->connect_header) == -1){
                    ERROR("Reply: not enough space!\n");
                }
                else{
                    socks5_p->state = FINISHED;
                    return;
                }
            default:
                return;
            break;
        }
    }

}

void passive_accept(struct selector_key *key){
    
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    int newsockfd = accept(key->fd,(struct sockaddr *)&cli_addr, &clilen);
    
    if (newsockfd < 0 )
       ERROR("Socks passive accept: bad file descriptor\n");

    Socks5HandlerP socks5_p = get_socks5_handler();
    if(socks5_p == NULL)
        ERROR("Socks passive accept: no space for new connection\n");


    socks5_p->state = HELLO;
    socks5_p->fd = newsockfd;
    buffer_init(&socks5_p->input, BUFSIZ, malloc(BUFSIZ));
    buffer_init(&socks5_p->output, BUFSIZ, malloc(BUFSIZ));
    hello_parser_init(&socks5_p->hello_parser);
    socks5_p->hello_parser.data = &socks5_p->auth_header;
    ((AuthHeader*)socks5_p->hello_parser.data)->size = 0;
    socks5_p->hello_parser.on_auth_method = on_auth_method;
    request_parser_init(&socks5_p->request_parser);
    socks5_p->fd_handler.handle_read = socks5_client_input;
    socks5_p->fd_handler.handle_write = socks5_client_output;

    selector_register(key->s, newsockfd, &socks5_p->fd_handler, OP_READ|OP_WRITE, socks5_p);
}

Socks5Handler * get_socks5_handler() {
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
        if(connections[i].asigned == 0){
            connections[i].asigned = 1;
            return &connections[i].handler;
        }
    }
    return NULL;
}

