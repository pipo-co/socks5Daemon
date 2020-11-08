#ifndef ADMIN_REQUEST_MODIFIERS_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_MODIFIERS_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "parsers/adminRequestParser/adminRequestParser.h"

bool admin_request_parser_add_user(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_remove_user(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_toggle_password_spoofing(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_toggle_connection_clean_up(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_set_buffer_size(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_set_selector_timeout(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_set_connection_timeout(struct AdminRequestParser *p, Buffer *b);

#endif