#include "parsers/adminRequestParser/adminRequestParserModifiers.h"
#include "adminResponseBuilder.h"

#include "userHandler/userHandler.h"
#include "socks5/socks5.h"

extern bool update_socks5_selector_timeout(time_t timeout);


AdminResponseBuilderContainer admin_request_parser_add_user(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    uint8_t status = 0x00;

    if(args->user.admin > 0x01) {
        status = 0x02;
    }

    else if(!user_handler_user_exists(args->user.uname, NULL)) {
        status = 0x01;
    }

    else if(user_handler_get_total_users() >= MAX_USER_COUNT) {
        status = 0x03;
    }

    else {
        UserInfoP user = user_handler_add_user(args->user.uname, args->user.pass, args->user.admin);
    
        if(user == NULL) {
            status = 0xFF;
        }
    }

    AdminResponseBuilderContainer container = {
        .type = type,
        .cmd = cmd,
        .currByte = 0,
        .data.uint8 = status,
        .admin_response_builder = admin_response_builder_uint8,
    };

    return container;
}

AdminResponseBuilderContainer admin_request_parser_remove_user(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    uint8_t status = 0x00;

    if(!user_handler_user_exists(args->user.uname, NULL)) {
        status = 0x01;
    }

    else {
        bool deleteStatus = user_handler_delete_user(args->string);
        if(deleteStatus == false) {
            status = 0xFF;
        }
    }

    AdminResponseBuilderContainer container = {
        .type = type,
        .cmd = cmd,
        .currByte = 0,
        .data.uint8 = status,
        .admin_response_builder = admin_response_builder_uint8,
    };

    return container;
}

AdminResponseBuilderContainer admin_request_parser_toggle_password_spoofing(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    AdminResponseBuilderContainer container;

    // TODO: code function

    return container;
}

AdminResponseBuilderContainer admin_request_parser_toggle_connection_clean_up(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    uint8_t status = 0x00;

    if(args->uint8 > 1) {
        status = 0x01;
    }

    else {
        Socks5Args *serverArgs = socks5_get_args();

        serverArgs->disectors_enabled = args->uint8;
    }

    AdminResponseBuilderContainer container = {
        .type = type,
        .cmd = cmd,
        .currByte = 0,
        .data.uint8 = status,
        .admin_response_builder = admin_response_builder_uint8,
    };

    return container;
}

AdminResponseBuilderContainer admin_request_parser_set_buffer_size(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    uint8_t status = 0x00;

    if(socks5_set_io_buffer_size(args->uint32) == false) {
        status = 0x01;
    }

    AdminResponseBuilderContainer container = {
        .type = type,
        .cmd = cmd,
        .currByte = 0,
        .data.uint8 = status,
        .admin_response_builder = admin_response_builder_uint8,
    };

    return container;
}

AdminResponseBuilderContainer admin_request_parser_set_selector_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    uint8_t status = 0x00;

    if(update_socks5_selector_timeout(args->uint8) == false) {
        status = 0x01;
    }

    AdminResponseBuilderContainer container = {
        .type = type,
        .cmd = cmd,
        .currByte = 0,
        .data.uint8 = status,
        .admin_response_builder = admin_response_builder_uint8,
    };

    return container;
}

AdminResponseBuilderContainer admin_request_parser_set_connection_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args) {

    uint8_t status = 0x00;

    if(socks5_set_max_session_inactivity(args->uint8) == false) {
        status = 0x01;
    }

    AdminResponseBuilderContainer container = {
        .type = type,
        .cmd = cmd,
        .currByte = 0,
        .data.uint8 = status,
        .admin_response_builder = admin_response_builder_uint8,
    };

    return container;
}