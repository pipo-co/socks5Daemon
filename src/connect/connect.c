#include <stdio.h>
#include <stdlib.h>
#include "connect.h"

void establishConnectionIp4(Socks5HandlerP socks5_p){
    
    int sock;
	struct sockaddr_in servaddr; 
  
    // socket create and varification 
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (sock == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    
	bzero(&servaddr, sizeof(servaddr)); 
    // assign IP, PORT 
    servaddr.sin_family = PF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(socks5_p->request_parser.address); 
    servaddr.sin_port = htons(socks5_p->request_parser.port);

    if (connect(sock, (struct sockaddr*) &servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
        exit(0); 
    } 
    else
        printf("connected to the server..\n"); 
	
}
