#ifndef ADMIN_RESPONSE_BUILDER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_RESPONSE_BUILDER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "buffer/buffer.h"
#include "userHandler/userHandler.h"

#define UINT8_RESPONSE_SIZE 3
#define UINT16_RESPONSE_SIZE 4
#define UINT32_RESPONSE_SIZE 6
#define UINT64_RESPONSE_SIZE 10
#define MASK 0xff
#define USER 0
#define ADMIN 1
#define INITIAL_HEADER 2
typedef struct UserListResponseData {
    int currentUser;
    int totalUsers;
    UserInfoP users[MAX_USER_COUNT];
} UserListResponseData;

typedef union CommandResponseBuilderData {
        uint8_t uint8;
        uint16_t uint16;
        uint32_t uint32;
        uint64_t uint64;
        UserListResponseData userList;
} CommandResponseBuilderData;

typedef struct AdminResponseBuilderContainer {
    uint16_t currByte;

    uint8_t type;
    uint8_t cmd;

    CommandResponseBuilderData data;

    bool (*admin_response_builder)(struct AdminResponseBuilderContainer *, Buffer *);

} AdminResponseBuilderContainer;

bool admin_response_builder_uint8(AdminResponseBuilderContainer * adminResponse, Buffer * b);

bool admin_response_builder_uint16(AdminResponseBuilderContainer * adminResponse, Buffer * b);

bool admin_response_builder_uint32(AdminResponseBuilderContainer * adminResponse, Buffer * b);

bool admin_response_builder_uint64(AdminResponseBuilderContainer * adminResponse, Buffer * b);

bool admin_response_builder_user_list(AdminResponseBuilderContainer * adminResponse, Buffer * b);


#endif