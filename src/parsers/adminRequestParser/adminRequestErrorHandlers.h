#ifndef ADMIN_REQUEST_ERROR_HANDLERS_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_ERROR_HANDLERS_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "parsers/adminRequestParser/adminRequestParser.h"

void admin_request_error_handler_invalid_type(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_error_handler_invalid_query(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_error_handler_invalid_modification(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

#endif
