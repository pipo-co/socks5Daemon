    #include "adminResponseBuilder.h"

bool admin_response_builder_uint8(AdminResponseBuilderContainer * adminResponse, Buffer * b){
    uint16_t * currByte = &adminResponse->currByte;
    
    while(*currByte < UINT8_RESPONSE_SIZE && buffer_can_write(b)){
        if(*currByte == 0){
            (*currByte)++;
            buffer_write(b, adminResponse->type);
        }
        else if (*currByte == 1){
            (*currByte)++;
            buffer_write(b, adminResponse->cmd);
        }
        else {
            (*currByte)++;
            buffer_write(b, adminResponse->data.uint8);
        }
    }
    if(*currByte == UINT8_RESPONSE_SIZE){
        return true;
    }
    
    return false;
}

bool admin_response_builder_uint16(AdminResponseBuilderContainer * adminResponse, Buffer * b){
    uint16_t * currByte = &adminResponse->currByte;
    uint8_t aux;
    while(*currByte < UINT16_RESPONSE_SIZE && buffer_can_write(b)){
        if(*currByte == 0){
            (*currByte)++;
            buffer_write(b, adminResponse->type);
        }
        else if (*currByte == 1){
            (*currByte)++;
            buffer_write(b, adminResponse->cmd);
        }
        else {
            (*currByte)++;
            aux = (adminResponse->data.uint16 >> ((UINT16_RESPONSE_SIZE - *currByte)* 8)) & MASK;
            buffer_write(b, aux);
        }
    }
    if(*currByte == UINT16_RESPONSE_SIZE){
        return true;
    }
    
    return false;
}

bool admin_response_builder_uint32(AdminResponseBuilderContainer * adminResponse, Buffer * b){
    uint16_t * currByte = &adminResponse->currByte;
    uint8_t aux;
    while(*currByte < UINT32_RESPONSE_SIZE && buffer_can_write(b)){
        if(*currByte == 0){
            (*currByte)++;
            buffer_write(b, adminResponse->type);
        }
        else if (*currByte == 1){
            (*currByte)++;
            buffer_write(b, adminResponse->cmd);
        }
        else {
            (*currByte)++;
            aux = (adminResponse->data.uint16 >> ((UINT32_RESPONSE_SIZE - *currByte)* 8)) & MASK;
            buffer_write(b, aux);
        }
    }
    if(*currByte == UINT32_RESPONSE_SIZE){
        return true;
    }
    
    return false;
}

bool admin_response_builder_uint64(AdminResponseBuilderContainer * adminResponse, Buffer * b){
    uint16_t * currByte = &adminResponse->currByte;
    uint8_t aux;
    while(*currByte < UINT64_RESPONSE_SIZE && buffer_can_write(b)){
        if(*currByte == 0){
            (*currByte)++;
            buffer_write(b, adminResponse->type);
        }
        else if (*currByte == 1){
            (*currByte)++;
            buffer_write(b, adminResponse->cmd);
        }
        else {
            (*currByte)++;
            aux = adminResponse->data.uint16 >> ((UINT64_RESPONSE_SIZE - *currByte)* 8) & MASK;
            buffer_write(b, aux);
        }
    }
    if(*currByte == UINT64_RESPONSE_SIZE){
        return true;
    }
    
    return false;
}

bool admin_response_builder_user_list(AdminResponseBuilderContainer * adminResponse, Buffer * b){
    uint16_t * currByte = &adminResponse->currByte;
    int * currentUser = &adminResponse->data.userList.currentUser;
    int totalUsers = adminResponse->data.userList.totalUsers;
    char aux;

    while(*currentUser < totalUsers && buffer_can_write(b)){
        if(*currByte == 0){
            (*currByte)++;
            buffer_write(b, adminResponse->type);
        }
        else if (*currByte == 1){
            (*currByte)++;
            buffer_write(b, adminResponse->cmd);
        }
        else {
            if((aux = adminResponse->data.userList.users[*currentUser].username[*currByte - INITIAL_HEADER]), aux != '\0'){
                (*currByte)++;
                buffer_write(b, aux);
            }
            else{
                buffer_write(b, adminResponse->data.userList.users[*currentUser].admin ? USER:ADMIN);
                (*currentUser)++;
                *currByte = 2;
            }  
        }
    }

    if(*currentUser == totalUsers){
        return true;
    }
    
    return false;
}

bool admin_response_builder_simple_error(AdminResponseBuilderContainer * adminResponse, Buffer * b) {
    uint16_t * currByte = &adminResponse->currByte;
    uint8_t aux;

    while(*currByte < ERROR_RESPONSE_SIZE && buffer_can_write(b)){

        if(*currByte == 0){
            (*currByte)++;
            buffer_write(b, adminResponse->type);
        }

        else {
            (*currByte)++;
            buffer_write(b, adminResponse->cmd);
        }
    }

    if(*currByte == ERROR_RESPONSE_SIZE){
        return true;
    }
    
    return false;
}
