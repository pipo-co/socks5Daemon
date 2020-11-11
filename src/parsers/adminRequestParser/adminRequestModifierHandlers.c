#include "parsers/adminRequestParser/adminRequestModifierHandlers.h"
#include "adminResponseBuilder.h"

#include "userHandler/userHandler.h"
#include "socks5/socks5.h"

#include <string.h>


void admin_request_parser_add_user(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(args->user.admin > 0x01 || *args->user.uname == 0 || *args->user.pass == 0) {
        status = 0xFE;
    }

    else if(user_handler_user_exists(args->user.uname, NULL)) {
        status = 0x01;
    }

    else if(user_handler_get_total_users() >= MAX_USER_COUNT) {
        status = 0x02;
    }

    else {
        UserInfoP user = user_handler_add_user(args->user.uname, args->user.pass, args->user.admin);
    
        if(user == NULL) {
            status = 0xFF;
        }
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_remove_user(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(args->string == NULL || args->string[0] == 0 || strcmp(args->string, ANONYMOUS_USER_CREDENTIALS) == 0) {
        status = 0xFE;
    }

    else if(!user_handler_user_exists(args->string, NULL)) {
        status = 0x01;
    }

    else {
        bool deleteStatus = user_handler_delete_user(args->string);

        if(deleteStatus == false) {
            status = 0xFF;
        }
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_toggle_password_spoofing(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(args->uint8 > 1) {
        status = 0xFE;
    }

    else {

        Socks5Args *serverArgs = socks5_get_args();

        serverArgs->disectors_enabled = args->uint8;
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_toggle_connection_clean_up(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(args->uint8 > 1) {
        status = 0xFE;
    }

    else {
        Socks5Args *serverArgs = socks5_get_args();

        serverArgs->disectors_enabled = args->uint8;
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_set_buffer_size(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(socks5_set_io_buffer_size(args->uint32) == false) {
        status = 0x01;
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_set_selector_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(socks5_update_selector_timeout(args->uint8) == false) {
        status = 0x01;
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_set_connection_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t status = 0x00;

    if(socks5_set_max_session_inactivity(args->uint8) == false) {
        status = 0x01;
    }

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}