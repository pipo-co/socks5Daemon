#ifndef USER_HANDLER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define USER_HANDLER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdbool.h>
#include <stdint.h>

#define ANONYMOUS_USER_CREDENTIALS "anonymous"

// Maximo 255 usuarios

typedef struct UserInfo {

    char *username;
    char *password;

    uint16_t connectionCount; 

} UserInfo;

typedef UserInfo * UserInfoP;

void user_handler_init(void);

bool user_handler_user_exists(char *username);

UserInfoP user_handler_get_user_by_username(char *username);

UserInfoP user_handler_add_user(char *username, char *password);

bool user_handler_delete_user(char *username);

void user_handler_destroy(void);

#endif