#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr) {
    if(addr == 0) {
        strncpy(buff, "null", buffsize);
        return buff;
    }
    in_port_t port;
    void *p = 0x00;
    bool handled = false;

    switch(addr->sa_family) {
        case AF_INET:
            p    = &((struct sockaddr_in *) addr)->sin_addr;
            port =  ((struct sockaddr_in *) addr)->sin_port;
            handled = true;
            break;
        case AF_INET6:
            p    = &((struct sockaddr_in6 *) addr)->sin6_addr;
            port =  ((struct sockaddr_in6 *) addr)->sin6_port;
            handled = true;
            break;
    }
    if(handled) {
        if (inet_ntop(addr->sa_family, p,  buff, buffsize) == 0) {
            strncpy(buff, "unknown ip", buffsize);
            buff[buffsize - 1] = 0;
        }
    } else {
        strncpy(buff, "unknown", buffsize);
    }

    strncat(buff, ":", buffsize);
    buff[buffsize - 1] = 0;
    const size_t len = strlen(buff);

    if(handled) {
        snprintf(buff + len, buffsize - len, "%d", ntohs(port));
    }
    buff[buffsize - 1] = 0;

    return buff;
}

int
sock_blocking_write(const int fd, Buffer *b) {
        int  ret = 0;
    ssize_t  nwritten;
	 size_t  n;
	uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int
sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char* out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
    error:

    return ret;
}

int new_ipv4_socket(char *ip, uint16_t port) {
	
	int sock;
	struct sockaddr_in addr; 
  
    // socket create and varification 
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (sock == -1) { 
        return -1;
    } 
    
	bzero(&addr, sizeof(addr)); 

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port); 
	inet_pton(AF_INET, ip, &addr.sin_addr.s_addr);

	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0) { 
        if(errno == EINPROGRESS)
            return sock;
        return -1;
    } 

	return sock;
}

int new_ipv6_socket(char *ip, uint16_t port) {
	
	int sock;
	struct sockaddr_in6 addr; 
  
    // socket create and varification 
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); 
    if (sock == -1) { 
        return -1;
    } 
    
	bzero(&addr, sizeof(addr)); 

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port); 
	inet_pton(AF_INET6, ip, &addr.sin6_addr);

	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0) { 
        if(errno == EINPROGRESS)
            return sock;
        return -1;
    } 

	return sock;
}

