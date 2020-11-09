#include "parsers/adminRequestParser/adminRequestQueryHandlers.h"
#include "adminResponseBuilder.h"

#include "userHandler/userHandler.h"
#include "statistics/statistics.h"
#include "socks5/socks5.h"

static void admin_request_parser_list_users_free(AdminResponseBuilderContainer *container);

void admin_request_parser_list_users(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    uint8_t userCount = user_handler_get_total_users();

    outContainer->data.userList.users = malloc(userCount * sizeof(UserInfo));

    // General Server Error
    if(outContainer->data.userList.users == NULL) {

        outContainer->type = type;
        outContainer->cmd = 0xFE;
        outContainer->currByte = 0;
        outContainer->data.uint8 = 0xFF;
        outContainer->admin_response_builder = admin_response_builder_uint8;
        outContainer->admin_response_free_data = NULL;

        return;
    }

    // Fill User List
    user_handler_get_all_users(outContainer->data.userList.users);

    outContainer->data.userList.totalUsers = userCount;
    outContainer->data.userList.currentUser = 0;

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->admin_response_builder = admin_response_builder_user_list;
    outContainer->admin_response_free_data = admin_request_parser_list_users_free;
}

static void admin_request_parser_list_users_free(AdminResponseBuilderContainer *container) {
    free(container->data.userList.users);
    container->data.userList.users = NULL;
}


void admin_request_parser_total_historic_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint64 = statistics.totalConnections;
    outContainer->admin_response_builder = admin_response_builder_uint64;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_current_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    
    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint16 = statistics.currentConnections;
    outContainer->admin_response_builder = admin_response_builder_uint16;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_max_current_conections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint16 = statistics.maxConcurrentConnections;
    outContainer->admin_response_builder = admin_response_builder_uint16;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_total_bytes_sent(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint64 = statistics.bytesSent;
    outContainer->admin_response_builder = admin_response_builder_uint64;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_total_bytes_received(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint64 = statistics.bytesReceived;
    outContainer->admin_response_builder = admin_response_builder_uint64;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_connected_users(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = statistics.currentUserCount;
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_user_count(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = user_handler_get_total_users();
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_buffer_sizes(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint32 = socks5_get_io_buffer_size();
    outContainer->admin_response_builder = admin_response_builder_uint32;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_selector_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = socks5_get_selector_timeout();
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_connection_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    
    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = socks5_get_max_session_inactivity();
    outContainer->admin_response_builder = admin_response_builder_uint8;
    outContainer->admin_response_free_data = NULL;
}

void admin_request_parser_user_total_concurrent_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    UserInfoP user = user_handler_get_user_by_username(args->string);

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint16 = (user == NULL)? 0 : user->connectionCount;
    outContainer->admin_response_builder = admin_response_builder_uint16;
    outContainer->admin_response_free_data = NULL;
}