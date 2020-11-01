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

int request_marshall(Buffer *b, uint8_t addr_type)
{
    size_t n, j = 0;
    uint8_t *buffer = buffer_write_ptr(b, &n);

    //podria tener el connect header calculado el size de la response
    if (n < REPLY_SIZE)
        return -1;

    //TODO: hay que hacer este metodo
    buffer[j++] = SOCKS_VERSION;
    buffer[j++] = 0; //cambiar a la que corresponda
    buffer[j++] = 0;
    buffer[j++] = addr_type;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;
    buffer[j++] = 0;

    buffer_write_adv(b, j);

    printf("started printing response \n");
    for (size_t i = 0; i < j; i++)
    {
        printf("buffer[%d] = %c\n", i, buffer[i]);
    }
    return j;
}

