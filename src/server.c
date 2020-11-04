/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "selector/selector.h"
#include "netutils/netutils.h"
#include "socks5/socks5.h"
//#include "socks5nio.h"

#define SERVER_BACKLOG 20

static int generate_new_socket(struct sockaddr *addr, socklen_t addrLen,char ** errorMessage);
static void sigterm_handler(const int signal);
static int generate_register_ipv4_socket(FdSelector selector, char **errorMessage);
static int generate_register_ipv6_socket(FdSelector selector, char **errorMessage);
static FdSelector initialize_selector(char ** errorMessage);


struct ServerHandler {
    struct in_addr ipv4addr;
    struct in6_addr ipv6addr;
    in_port_t port;
    struct FdHandler ipv6Handler;
    struct FdHandler ipv4Handler;
    int ipv4Fd;
    int ipv6Fd;
};

static struct ServerHandler serverHandler;
static bool done = false;

int main(const int argc, const char **argv) {
    
    serverHandler.port = htons(1080);

    if(argc == 1) {
        // utilizamos el default
    } else if(argc == 2) {
        char *end     = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1]|| '\0' != *end 
           || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
           || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "port should be an integer: %s\n", argv[1]);
            return 1;
        }
        serverHandler.port = htons(sl);
    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    char       *err_msg      = NULL;
    SelectorStatus   ss      = SELECTOR_SUCCESS;
    
    FdSelector selector = initialize_selector(&err_msg);
    
    if(selector == NULL) {
        goto finally;
    }

    serverHandler.ipv4addr.s_addr = htonl(INADDR_ANY);
    
    if(generate_register_ipv4_socket(selector, &err_msg) != 0) {
         goto finally;
    }
    
    inet_pton(AF_INET6, "::1", &serverHandler.ipv6addr);

    if(generate_register_ipv6_socket(selector, &err_msg) != 0) {
         goto finally;
    }

    socks5_init("8.8.8.8");

    while(!done) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;

finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    // socksv5_pool_destroy();

    if(serverHandler.ipv4Fd >= 0) {
        close(serverHandler.ipv4Fd);
    }

    if(serverHandler.ipv6Fd >= 0) {
        close(serverHandler.ipv6Fd);
    }
    return ret;
}


static FdSelector initialize_selector(char ** errorMessage) {

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    if(selector_init(&conf) != 0) {
        *errorMessage = "Initializing selector";
        return NULL;
    }

    FdSelector selector = selector_new(1024);
    if(selector == NULL) {
        *errorMessage = "Unable to create selector";
        return NULL;
    }

    return selector;
}

static int generate_register_ipv4_socket(FdSelector selector, char **errorMessage) {

    memset(&serverHandler.ipv4Handler, '\0', sizeof(serverHandler.ipv4Handler));

    serverHandler.ipv4Handler.handle_read = socks5_passive_accept_ipv4;
    
    struct sockaddr_in sockaddr4 = {
        .sin_addr = serverHandler.ipv4addr,
        .sin_family = AF_INET,
        .sin_port = serverHandler.port,
    };

    int ipv4Fd = generate_new_socket((struct sockaddr *)&sockaddr4, sizeof(sockaddr4), errorMessage);
    if(ipv4Fd == -1) {
        return -1;
    }

    if(selector_register(selector, ipv4Fd, &serverHandler.ipv4Handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        *errorMessage = "Registering fd for ipv4";
        return -1;
    }

    serverHandler.ipv4Fd = ipv4Fd;
    return 0;
}

static int generate_register_ipv6_socket(FdSelector selector, char **errorMessage) {
     
    memset(&serverHandler.ipv6Handler, '\0', sizeof(serverHandler.ipv6Handler));

    serverHandler.ipv6Handler.handle_read = socks5_passive_accept_ipv6;

    struct sockaddr_in6 sockaddr6 = {
        .sin6_addr = serverHandler.ipv6addr,
        .sin6_family = AF_INET6,
        .sin6_port = serverHandler.port,
    };

    int ipv6Fd = generate_new_socket((struct sockaddr *)&sockaddr6, sizeof(sockaddr6), errorMessage);
    if(ipv6Fd == -1) {
        return -1;
    }

    if(selector_register(selector, ipv6Fd, &serverHandler.ipv6Handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        *errorMessage = "Registering fd for ipv6";
        return -1;
    }

    serverHandler.ipv6Fd = ipv6Fd;
    return 0;
}

static int generate_new_socket(struct sockaddr *addr, socklen_t addrLen,char ** errorMessage) {

    const int fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0) {
       *errorMessage = "Unable to create socket";
       return -1;
    }

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    if(bind(fd, addr, addrLen) < 0) {
        *errorMessage = "Unable to bind socket";
        return -1;
    }

    if(listen(fd, SERVER_BACKLOG) < 0) {
        *errorMessage = "Unable to listen";
        return -1;
    }

    if(selector_fd_set_nio(fd) == -1) {
        *errorMessage = "Getting server socket flags";
        return -1;
    }
    return fd;
}

static void sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}