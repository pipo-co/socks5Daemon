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
#include "buffer.h"

#define SOCKS_VERSION 0x05

typedef enum { PORT_SIZE = 2, MAX_ADDR = 255, REPLY_SIZE = 22} ConnectSize;

typedef enum { TYPE_IP4 = 0x01, TYPE_DOMAIN_NAME = 0x03 , TYPE_IP6 = 0x04
}ConnectIpEnum;
typedef struct {
    int sock;
    uint8_t addr_type;
    uint16_t protocol;
    char dst_addr[MAX_ADDR]; //TODO esto es bastante ineficiente en cuanto a memoria
    char port[PORT_SIZE];
}ConnectHeader;

int establishConnectionIp4(ConnectHeader *connect_header);

void connectHeaderInit(ConnectHeader * connect_header, uint8_t addr_type, uint8_t * addr, size_t addr_lenght, uint8_t * port);

int request_marshall(Buffer * b, ConnectHeader * connect_header);

#endif