#ifndef CONNECT_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define CONNECT_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <arpa/inet.h>
#include <netinet/in.h> 
#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#define PORT_SIZE 2
#define MAX_ADDR 255

typedef struct {
    int sock;
    char dst_addr[MAX_ADDR]; //TODO esto es bastante ineficiente en cuanto a memoria
    char port[PORT_SIZE];
}ConnectHeader;

int establishConnectionIp4(ConnectHeader *connect_header);

#endif