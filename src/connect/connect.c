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
    
    // struct in_addr a;

    // if(inet_pton(AF_INET, &a, &connect_header->dst_addr) == 1)

    return connect(connect_header->sock, (struct sockaddr*) &servaddr, sizeof(servaddr));

}

void connectHeaderInit(ConnectHeader * connect_header, uint8_t addr_type, char * addr, size_t addr_lenght, char * port){
    connect_header->addr_type = addr_type;
    memcpy(connect_header->dst_addr, addr, addr_lenght);
    memcpy(connect_header->port, port, PORT_SIZE);
}

int request_marshall(Buffer * b, ConnectHeader * connect_header){
    size_t n, j = 0;
    uint8_t *buffer = buffer_write_ptr(b, &n);

    if ( n < REPLY_SIZE )
        return -1;
    
    buffer[j++] = SOCKS_VERSION;
    buffer[j++] = 0; //cambiar a la que corresponda
    buffer[j++] = 0;
    buffer[j++] = connect_header->addr_type;
    if(connect_header->addr_type == REQUEST_ADD_TYPE_IP4){
        parseIp4Addr(buffer, &j, connect_header->dst_addr);
    }
    buffer[j++] = connect_header->port[1];
    buffer[j++] = connect_header->port[0];

    buffer_write_adv(b, j);
    
    return j;
    
}
void parseIp4Addr(uint8_t * buffer, size_t *j, char * addr){
    for (size_t i = 0; *addr != 0; i++)
    {
        if(addr[i] != '.')
            buffer[(*j)++] = addr[i];
    }
    
}