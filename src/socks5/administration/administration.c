#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#define QUERY_BUFFER 128


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

void administration_handler(SelectorEvent *event){
    
    int fd, in;
    struct sockaddr_in cli_addr;
    struct sctp_sndrcvinfo sndrcvinfo;
    socklen_t clilen = sizeof(cli_addr);
    char buffer[QUERY_BUFFER];
    

    fd = sctp_accept_connection(event->fd, (struct sockaddr *)&cli_addr, &clilen);

    if(fd < 0) {
        return;
    }

    in = sctp_recvmsg(conn_fd, buffer, sizeof(buffer), NULL, 0, &sndrcvinfo, &flags);


    fprintf(stderr, "Registered new client %d\n", fd);
}

                