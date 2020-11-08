#ifndef ADMIN_RESPONSE_BUILDER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_RESPONSE_BUILDER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "buffer/buffer.h"
#include "userHandler/userHandler.h"

typedef struct UserListResponseData {

    UserInfoP users[255];

} UserListResponseData;

typedef union CommandResponseBuilderData {
        uint8_t uint8;
        uint16_t uint16;
        uint32_t uint32;
        uint64_t uint64;
        UserListResponseData userList;
} CommandResponseBuilderData;

typedef struct AdminResponseBuilderContainer {
    int currByte;

    uint8_t type;
    uint8_t cmd;

    CommandResponseBuilderData data;

    void (*admin_response_builder)(AdminResponseBuilderContainer *, Buffer *);

} AdminResponseBuilderContainer;


#endif