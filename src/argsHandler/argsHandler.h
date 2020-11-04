#ifndef ARGS_H_VelRDAxzvnuFmwyaR0ftrkIinkT
#define ARGS_H_VelRDAxzvnuFmwyaR0ftrkIinkT

#include <stdbool.h>

#define MAX_USERS 10

struct users {
    char *name;
    char *pass;
};

struct doh {
    char           *host;
    char           *ip;
    unsigned short  port;
    char           *path;
    char           *query;
};

typedef struct Socks5Args {
    char           *socks_addr;
    unsigned short  socks_port;

    char *          mng_addr;
    unsigned short  mng_port;

    bool            disectors_enabled;

    struct doh      doh;

    int user_count;
    struct users    users[MAX_USERS];
} Socks5Args;

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void 
parse_args(const int argc, char **argv, Socks5Args *args);

#endif
