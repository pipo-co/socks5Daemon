
#include "userHandler.h"

#include "utilities/khash.h"

KHASH_MAP_INIT_STR(STRING_TO_CHAR_MAP, UserInfoP)

typedef khash_t(STRING_TO_CHAR_MAP) * UserMap;

static UserMap userMap = NULL;

// iter == kh_end(userMap) equivale a decir que el valor no pertenece al mapa

static UserInfoP user_handler_create_user(char *username, char *password, bool admin);
static void user_handler_free_user(UserInfoP user);

void user_handler_init(void) {
    userMap = kh_init(STRING_TO_CHAR_MAP);

    // Anonymous User
    user_handler_add_user(ANONYMOUS_USER_CREDENTIALS, ANONYMOUS_USER_CREDENTIALS, false);
}

bool user_handler_user_exists(char *username, bool *admin) {
    khiter_t iter = kh_get(STRING_TO_CHAR_MAP, userMap, username);
    
    if(iter != kh_end(userMap)){
        if(admin != NULL){
            UserInfoP u = kh_value(userMap, iter);
            *admin = u->admin;
        }
        return true;
    }

    return false;
}

uint8_t user_handler_get_total_users(void) {
    return kh_size(userMap);
}

UserInfoP user_handler_get_user_by_username(char *username) {

    khiter_t iter = kh_get(STRING_TO_CHAR_MAP, userMap, username);

    if(iter != kh_end(userMap)) {
        return kh_value(userMap, iter);
    }

    return NULL;
}

uint8_t user_handler_get_all_users(UserInfoP output[]) {

    uint8_t iter = 0;

    for (khiter_t k = kh_begin(userMap); k != kh_end(userMap); k++) {

		if(kh_exist(userMap, k)) {
            output[iter++] = kh_value(userMap, k);
        }
    }

    return iter;
}

UserInfoP user_handler_add_user(char *username, char *password, bool admin) {

    if(kh_size(userMap) >= MAX_USER_COUNT){
        return NULL;
    }

    if(user_handler_user_exists(username, NULL)) {
        return NULL;
    }

    UserInfoP newUser = user_handler_create_user(username, password, admin);
    if(newUser == NULL) {
        return NULL;
    }

    int ret;

    khiter_t iter = kh_put(STRING_TO_CHAR_MAP, userMap, username, &ret);
    if(ret < 0) {
        free(newUser);
        return NULL;
    }

    kh_value(userMap, iter) = newUser;

    return newUser;
}

bool user_handler_delete_user(char *username) {
    khiter_t iter = kh_get(STRING_TO_CHAR_MAP, userMap, username);

    if(iter != kh_end(userMap)) {

        user_handler_free_user(kh_value(userMap, iter));
        kh_del(STRING_TO_CHAR_MAP, userMap, iter);

        return true;
    }

    return false;
}

void user_handler_destroy(void) {

    UserInfoP userIter;

    if(userMap == NULL){
        return;
    }

    kh_foreach_value(userMap, userIter, user_handler_free_user(userIter));

    kh_destroy(STRING_TO_CHAR_MAP, userMap);
}

static UserInfoP user_handler_create_user(char *username, char *password, bool admin) {

    UserInfoP newUser = malloc(sizeof(*newUser));
    if(newUser == NULL) {
        return NULL;
    }

    newUser->username = malloc((strlen(username) + 1) * sizeof(*username));
    if(newUser->username == NULL) {
        free(newUser);
        return NULL;
    }

    newUser->password = malloc((strlen(password) + 1) * sizeof(*password));
    if(newUser->password == NULL) {
        free(newUser);
        free(newUser->username);
        return NULL;
    }

    strcpy(newUser->username, username);
    strcpy(newUser->password, password);
    newUser->connectionCount = 0;
    newUser->admin = admin;

    return newUser;
}

static void user_handler_free_user(UserInfoP user) {
    free(user->username);
    free(user->password);
    free(user);
}