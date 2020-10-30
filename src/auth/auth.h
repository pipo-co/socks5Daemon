#ifndef AUTH_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B
#define AUTH_H_wL7YxN65ZHqKGvCPrNbPtMJgL8B

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include "hello.h"
#include "request.h"

typedef enum {
    NO_AUTH = 0,
    USER_PASSWORD = 2,
}MethodsState;

//TODO: mejorar esto
enum sizeConstants {
  METHOD_COUNT = 2,
  AUTH_FIELD_MAX_LENGHT = 255
};

enum UserPasswordAuthState {
    UP_VERSION,
    UP_U_LENGHT,
    UP_USERNAME,
    UP_P_LENGHT,
    UP_PASSWORD,
};

// Not an ADT to avoid unnecessary usages of malloc
typedef struct UserPasswordParser {

    void *data;

    enum UserPasswordAuthState current_state;

    char username[AUTH_FIELD_MAX_LENGHT];

    char password[AUTH_FIELD_MAX_LENGHT];

} AuthParser;

typedef struct {
    bool authenticated;
    uint8_t methods[METHOD_COUNT];
    size_t size;
    int auth_method;
   // void (*auth_parser)();
}AuthHeader;

void on_auth_method(HelloParser *p, uint8_t method);

void loadIfNotExist(AuthHeader *auth_header, uint8_t method);

int chooseAuthMethod(HelloParser *p);

#endif