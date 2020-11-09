#include "parsers/adminRequestParser/adminRequestErrorHandlers.h"

static void admin_request_error_handler_invalid_command(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_error_handler_invalid_type(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    outContainer->type = 0xFF;
    outContainer->cmd = cmd;
    outContainer->currByte = 0;
    outContainer->admin_response_builder = admin_response_builder_simple_error;
    outContainer->admin_response_free_data == NULL;
}

void admin_request_error_handler_invalid_query(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    admin_request_error_handler_invalid_command(type, cmd, args, outContainer);
}

void admin_request_error_handler_invalid_modification(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    admin_request_error_handler_invalid_command(type, cmd, args, outContainer);
}

static void admin_request_error_handler_invalid_command(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    
    outContainer->type = type;
    outContainer->cmd = 0xFF;
    outContainer->currByte = 0;
    outContainer->admin_response_builder = admin_response_builder_simple_error;
    outContainer->admin_response_free_data == NULL;
}
