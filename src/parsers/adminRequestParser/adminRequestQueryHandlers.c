#include "parsers/adminRequestParser/adminRequestQueryHandlers.h"
#include "adminResponseBuilder.h"

#include "userHandler/userHandler.h"

void admin_request_parser_list_users(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    // Fill User List
    uint8_t userCount = user_handler_get_all_users(outContainer->data.userList.users);

    outContainer->data.userList.totalUsers = userCount;
    outContainer->data.userList.currentUser = 0;

    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->admin_response_builder = admin_response_builder_user_list;
}


void admin_request_parser_total_historic_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {



    outContainer->type = type;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->data.uint8 = status;
    outContainer->admin_response_builder = admin_response_builder_uint8;
}

void admin_request_parser_current_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_max_current_conections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_total_bytes_sent(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_total_bytes_received(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_connected_users(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_user_count(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_buffer_sizes(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_selector_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_connection_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_user_total_concurrent_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);