#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include "connect.h"

extern int errno;

static void parseIp4Addr(uint8_t *buffer, size_t *j, uint8_t *addr)
{
    printf("parseIPV4\n");
    printf("%s\n", addr);
    for (size_t i = 0; addr[i] != 0; i++)
    {
        if (addr[i] != '.')
            putchar(buffer[(*j)++] = addr[i]);
    }
}

static uint16_t convertPort(uint8_t *port)
{
    //printf("port: %s\n", port);

    //printf("%5d %5d %5d %5d %5d",  port[0] - '0',  port[1] - '0',  port[2] - '0',  port[3] - '0',  port[4] - '0');
    uint16_t aux = 0;
    aux += port[4] - '0';
    aux += (port[3] - '0') * 10;
    aux += (port[2] - '0') * 100;
    aux += (port[1] - '0') * 1000;
    aux += (port[0] - '0') * 10000;
    return aux;
}

int establishConnectionIp4(ConnectHeader *connect_header)
{

    struct sockaddr_in servaddr;

    // socket create and varification
    connect_header->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect_header->sock == -1)
    {
        printf("socket creation failed...\n");
        while (1)
            ;
    }
    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(convertPort((uint8_t *)connect_header->port));

    if (inet_pton(AF_INET, connect_header->dst_addr, &servaddr.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // struct in_addr a;

    // if(inet_pton(AF_INET, &a, &connect_header->dst_addr) == 1)

    //printf("\nconnect_header->sock: %d, servaddr.sin_addr.s_addr: %u, servaddr.sin_port: %u, connect result: %d\n", connect_header->sock, connect_header->dst_addr, htons(convertPort(connect_header->port)), );
    // printf("errno: %d\n", errno);
    // perror("Error printed by perror\n");

    return connect(connect_header->sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
}

void connectHeaderInit(ConnectHeader *connect_header, uint8_t addr_type, uint8_t *addr, size_t addr_lenght, uint8_t *port)
{
    connect_header->addr_type = addr_type;
    memcpy(connect_header->dst_addr, addr, addr_lenght);
    memcpy(connect_header->port, port, 6);
}

int request_marshall(Buffer *b, ConnectHeader *connect_header)
{
    size_t n, j = 0;
    uint8_t *buffer = buffer_write_ptr(b, &n);

    //podria tener el connect header calculado el size de la response
    if (n < REPLY_SIZE)
        return -1;

    buffer[j++] = SOCKS_VERSION;
    buffer[j++] = 0; //cambiar a la que corresponda
    buffer[j++] = 0;
    buffer[j++] = connect_header->addr_type;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    // if(connect_header->addr_type == TYPE_IP4){
    //     parseIp4Addr(buffer, &j, connect_header->dst_addr);
    // }

    // buffer[j++] = connect_header->port[1];
    // buffer[j++] = connect_header->port[0];

    buffer_write_adv(b, j);

    printf("started printing response \n");
    for (size_t i = 0; i < j; i++)
    {
        printf("buffer[%d] = %c\n", i, buffer[i]);
    }
    return j;
}

