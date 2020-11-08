#include "parsers/adminRequestParser/adminRequestErrorHandlers.h"

static void admin_request_error_handler_invalid_command(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_error_handler_invalid_type(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

}

void admin_request_error_handler_invalid_query(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    admin_request_error_handler_invalid_command(type, cmd, args, outContainer);
}

void admin_request_error_handler_invalid_modification(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    admin_request_error_handler_invalid_command(type, cmd, args, outContainer);
}

static void admin_request_error_handler_invalid_command(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {
    
}
