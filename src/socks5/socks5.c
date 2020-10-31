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

static void process_information(ServerHandlerP p, uint8_t * buffer, size_t size){
    return;
}

static void forward_server_data_read(struct selector_key *key)
{
    ServerHandlerP server_p = (ServerHandlerP) key->data;

    if(!buffer_can_write(&server_p->input))
        return;
    
    
    size_t nbytes;
    ssize_t read_bytes;
    uint8_t * inputBuffer = buffer_write_ptr(&server_p->input, &nbytes);

     if((read_bytes = read(key->fd, inputBuffer, nbytes)) > 0){
        server_p->process_information(server_p, inputBuffer, nbytes);
        buffer_write_adv(&server_p->input, read_bytes);
    } else if (read_bytes == 0) {
        //Cerro la conexion
    }
    else
        ERROR("Socks client input: error reading")

}

static void forward_server_data_write(struct selector_key *key)
{

    ServerHandlerP server_p = (ServerHandlerP) key->data;

    if(!buffer_can_read(&server_p->output))
        return;

    size_t nbytes;
    ssize_t write_bytes;
    uint8_t * outputBuffer = buffer_read_ptr(&server_p->output, &nbytes);

    if ((write_bytes = write(key->fd, outputBuffer, nbytes)) > 0)
    {
        server_p->process_information(server_p, outputBuffer, nbytes);
        buffer_read_adv(&server_p->output, write_bytes);
        printf("bytes:%d\n", nbytes);
    }
}

static void register_server_socket(fd_selector s, Socks5HandlerP socks5_p){
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    int newsockfd = accept(socks5_p->connect_header.sock ,(struct sockaddr *)&cli_addr, &clilen);
    
    if (newsockfd < 0 )
       ERROR("Socks passive accept: bad file descriptor\n");

    ServerHandlerP server_p = (ServerHandler *) malloc(sizeof(ServerHandler));

    server_p->fd = newsockfd;
    server_p->input = socks5_p->output;
    server_p->output = socks5_p->input;
    server_p->fd_handler.handle_read = forward_server_data_read;
    server_p->fd_handler.handle_write = forward_server_data_write;
    server_p->process_information = process_information;
    server_p->data = NULL;

    selector_register(s, server_p->fd, &server_p->fd_handler, OP_READ|OP_WRITE, server_p);

}

static void socks5_process_input(Socks5HandlerP socks5_p, fd_selector selector) {
    // printf("socks5_p->state %d buffer_can_read %d\n", socks5_p->state, buffer_can_read(&socks5_p->input));
    bool errored;
    //TODO preguntar por condicion de salida del proccess input
    while(buffer_can_read(&socks5_p->input)){
        switch (socks5_p->state){
        case HELLO:
            hello_parser_consume(&socks5_p->input, &socks5_p->hello_parser, &errored);
            if(hello_is_done(socks5_p->hello_parser.current_state, &errored)){
                socks5_p->state = INITIAL_RESPONSE;
                printf("hello is done\n");
                return;
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
            printf("request\n");
            request_parser_consume(&socks5_p->input, &socks5_p->request_parser, &errored);
            if(request_is_done(socks5_p->request_parser.currentState, &errored)){
                socks5_p->state = EXECUTE_COMMAND;
                printf("request is done\n");
            }
            break;
        case FORWARDING:
            printf("processing server info\n");
            break;

        default:
            return;
        }
    }
}
static void socks5_process_output(Socks5HandlerP socks5_p, fd_selector selector) {
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
            case EXECUTE_COMMAND:
                connectHeaderInit(&socks5_p->connect_header, socks5_p->request_parser.addressType, socks5_p->request_parser.address, socks5_p->request_parser.addressLength, socks5_p->request_parser.port);
                if(socks5_p->request_parser.addressType == REQUEST_ADD_TYPE_IP4){
                    if(establishConnectionIp4(&socks5_p->connect_header) == -1)
                        return;

                    printf("Established connection on %s port %s\n", socks5_p->connect_header.dst_addr, socks5_p->connect_header.port);
                    register_server_socket(selector, socks5_p);
                    socks5_p->state = REPLY;
                    return;
                }
            break;
            case REPLY:
                printf("REPLYING\n");
                if(request_marshall(&socks5_p->output,&socks5_p->connect_header) == -1){
                    ERROR("Reply: not enough space!\n");
                }
                else{
                    socks5_p->state = FORWARDING;
                    return;
                }
            default:
                return;
            break;
        }
    }

}

static void socks5_client_input(struct selector_key *key){

    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    printf("Client input :buffer_can_write %d\n",!buffer_can_write(&socks5_p->input));
    if(!buffer_can_write(&socks5_p->input))
        return;
    
    ssize_t read_bytes;
    size_t nbytes;
    uint8_t * inputBuffer = buffer_write_ptr(&socks5_p->input, &nbytes);

    if((read_bytes = read(key->fd, inputBuffer, nbytes)) > 0){
        buffer_write_adv(&socks5_p->input, read_bytes);
        socks5_process_input(socks5_p, key->s);
    } else if (read_bytes == 0) {
        //Cerro la conexion
    }
    else
        ERROR("Socks client input: error reading")
}

static void socks5_client_output(struct selector_key *key){
    
    
    Socks5HandlerP socks5_p = (Socks5HandlerP) key->data;

    // printf("Client output: buffer_can_read %d\n",!buffer_can_read(&socks5_p->output));

    // printf("state = %d \n", socks5_p->state);
    socks5_process_output(socks5_p, key->s);

   // printf("about to can read\n");
    if(!buffer_can_read(&socks5_p->output))
        return;

    ssize_t write_bytes;
    size_t nbytes;
    uint8_t * outputBuffer = buffer_read_ptr(&socks5_p->output, &nbytes);
    
    if((write_bytes = write(key->fd, outputBuffer, nbytes)) > 0){
        buffer_read_adv(&socks5_p->output, write_bytes);
        printf("bytes:%d\n", nbytes);
    } else if (write_bytes == 0) {
        //Cerro la conexion
    }
    else
        ERROR("Socks client input: error reading")
    
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

    selector_register(key->s, socks5_p->fd, &socks5_p->fd_handler, OP_READ|OP_WRITE, socks5_p);
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

