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

void socks5_process_input(Socks5HandlerP socks5_p) {
    printf("socks5_p->state %d \n", socks5_p->state);
    bool errored;
    while(socks5_p->state != FINISHED){
        switch (socks5_p->state){
        case HELLO:
            hello_parser_consume(&socks5_p->input, &socks5_p->hello_parser, &errored);
            if(hello_is_done(socks5_p->hello_parser.current_state, &errored)){
                socks5_p->state = INITIAL_RESPONSE;
                
                printf("hello is done\n");
            }
            break;
        case INITIAL_RESPONSE:
            socks5_p->auth_method = chooseAuthMethod(&socks5_p->hello_parser);
            
            if(socks5_p->auth_method < 0){
                ERROR("Authentication method accept: invalid method!\n");
                return;
            }
            printf("auth method = %d\n",socks5_p->auth_method);
            socks5_p->state = AUTHENTICATION;

        case AUTHENTICATION:
            printf("authenticating");
            // auth_parser_consume(&socks5_p->input, &socks5_p->hello_parser, &errored);
            // if(auth_is_done(socks5_p->hello_parser.current_state, &errored)){
            //     socks5_p->state = AUTHENTICATION;
            //     printf("hello is done\n");
            // }
        default:
            break;
        }
    }

}

void passive_accept(struct selector_key *key){
    
    struct sockaddr_in cli_addr;
    int clilen = sizeof(cli_addr);
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

    selector_register(key->s, newsockfd, &socks5_p->fd_handler, OP_READ, socks5_p);
}

Socks5Handler * get_socks5_handler() {
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) {
        if(connections[i].asigned == 0){
            connections[i].asigned = 1;
            return connections + i;
        }
    }
    return NULL;
}

