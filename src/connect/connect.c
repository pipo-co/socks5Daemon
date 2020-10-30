#include <stdio.h>
#include <stdlib.h>
#include "connect.h"

int establishConnectionIp4(ConnectHeader *connect_header){
    
	struct sockaddr_in servaddr; 
  
    // socket create and varification 
    connect_header->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (connect_header->sock == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    
	bzero(&servaddr, sizeof(servaddr)); 
    // assign IP, PORT 
    servaddr.sin_family = PF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(connect_header->dst_addr); 
    servaddr.sin_port = htons(connect_header->port);

    return connect(connect_header->sock, (struct sockaddr*) &servaddr, sizeof(servaddr));

}

void connectHeaderInit(ConnectHeader * connect_header, char * addr, size_t addr_lenght, char * port){
    memcpy(connect_header->dst_addr, addr, addr_lenght);
    memcpy(connect_header->port, port, PORT_SIZE);
}