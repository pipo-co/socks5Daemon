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

#include "argsHandler/argsHandler.h"
#include "selector/selector.h"
#include "netutils/netutils.h"
#include "socks5/socks5.h"
#include "userHandler/userHandler.h"
#include "statistics/statistics.h"

#define SERVER_BACKLOG 20

#define DEFAULT_SELECT_TIMEOUT 7
#define DEFAULT_MAX_SESSION_INACTIVITY 7

static int generate_new_socket(struct sockaddr *addr, socklen_t addrLen,char ** errorMessage);
static void sigterm_handler(const int signal);
static int generate_register_ipv4_socket(FdSelector selector, char **errorMessage);
static int generate_register_ipv6_socket(FdSelector selector, char **errorMessage);
static FdSelector initialize_selector(char ** errorMessage);
static void initialize_users(void);


typedef struct ServerHandler {
    struct in_addr ipv4addr;
    struct in6_addr ipv6addr;
    in_port_t port;
    FdHandler ipv6Handler;
    FdHandler ipv4Handler;
    int ipv4Fd;
    int ipv6Fd;
} ServerHandler;

static Socks5Args args;
static ServerHandler serverHandler;
static bool done = false;


static double cleanupInterval;

int main(const int argc, char **argv) {

    parse_args(argc, argv, &args);
    
    serverHandler.port = htons(args.socks_port);

    // no tenemos nada que leer de stdin
    close(STDIN_FILENO);

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    // Non-Blocking stdout & stderr
    selector_fd_set_nio(stdout);
    selector_fd_set_nio(stderr);

    char       *err_msg      = NULL;
    SelectorStatus   ss      = SELECTOR_SUCCESS;
    int passiveSocketErrorCount = 0;
    
    FdSelector selector = initialize_selector(&err_msg);
    
    if(selector == NULL) {
        goto finally;
    }

        // Listen to all interfaces
    if(args.socks_addr == NULL) {
        serverHandler.ipv6addr = in6addr_any;

        serverHandler.ipv4addr.s_addr = htonl(INADDR_ANY);

        if(generate_register_ipv4_socket(selector, &err_msg) != 0) {
            fprintf(stdout, "Error registering IPv4 listening socket\n");
            perror(err_msg);
            fprintf(stdout, "Trying with IPv6\n\n");
            
            passiveSocketErrorCount++;
        }

        if(generate_register_ipv6_socket(selector, &err_msg) != 0) {
            fprintf(stdout, "Error registering IPv6 listening socket\n");

            if(passiveSocketErrorCount == 0) {
                perror(err_msg);
                fprintf(stdout, "Continuing with just IPv4\n");
            }
            else {
                goto finally;
            }
        }
    }

    // -l 
    else if(inet_pton(AF_INET, args.socks_addr, &serverHandler.ipv4addr)) {
        if(generate_register_ipv4_socket(selector, &err_msg) != 0) {
            goto finally;
        }
    } 
    
    else if (inet_pton(AF_INET6, args.socks_addr, &serverHandler.ipv6addr)) {
        if(generate_register_ipv6_socket(selector, &err_msg) != 0) {
            goto finally;
        }
    } 

    else {
        err_msg = "Invalid IP in -l parameter";
        goto finally;
    }

    statistics_init();

    initialize_users();

    socks5_init(&args, DEFAULT_MAX_SESSION_INACTIVITY);

    cleanupInterval = DEFAULT_SELECT_TIMEOUT;

    time_t lastFdCleanup = time(NULL);

    while(!done) {
        err_msg = NULL;
        ss = selector_select(selector);

        // Cleanup selector sockets every cleanupInterval seconds
        if(!args.debugEnable && difftime(time(NULL), lastFdCleanup) >= cleanupInterval) {
            fprintf(stdout, "Initializing Selector Cleanup\n");
            selector_fd_cleanup(selector, socks5_cleanup_session);
            lastFdCleanup = time(NULL);
        }

        // statistics_print(); For logs every iteration

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

    user_handler_destroy();

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
            .tv_sec  = DEFAULT_SELECT_TIMEOUT,
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

    if(addr->sa_family == AF_INET6) {
        setsockopt(fd, SOL_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));
    }

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

static void initialize_users(void) {

    user_handler_init();

    for(int i = 0; i < args.user_count; i++) {
        user_handler_add_user(args.users[i].name, args.users[i].pass);
    }
}