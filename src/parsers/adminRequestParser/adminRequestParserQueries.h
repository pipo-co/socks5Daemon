#ifndef ADMIN_REQUEST_QUERIES_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_QUERIES_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "parsers/adminRequestParser/adminRequestParser.h"

bool admin_request_parser_list_users(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_total_historic_connections(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_current_connections(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_max_current_conections(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_total_bytes_sent(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_total_bytes_received(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_connected_users(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_user_count(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_buffer_sizes(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_selector_timeout(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_connection_timeout(struct AdminRequestParser *p, Buffer *b);

bool admin_request_parser_user_total_concurrent_connections(struct AdminRequestParser *p, Buffer *b);

#endif