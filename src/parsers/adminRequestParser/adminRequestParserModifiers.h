#ifndef ADMIN_REQUEST_MODIFIERS_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_MODIFIERS_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "parsers/adminRequestParser/adminRequestParser.h"

RequestHandler admin_request_parser_add_user(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_remove_user(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_toggle_password_spoofing(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_toggle_connection_clean_up(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_set_buffer_size(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_set_selector_timeout(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_set_connection_timeout(AdminRequestParser *p, void *data);

#endif