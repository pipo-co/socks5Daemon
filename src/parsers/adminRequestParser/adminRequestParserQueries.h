#ifndef ADMIN_REQUEST_QUERIES_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_QUERIES_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "parsers/adminRequestParser/adminRequestParser.h"

RequestHandler admin_request_parser_list_users(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_total_historic_connections(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_current_connections(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_max_current_conections(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_total_bytes_sent(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_total_bytes_received(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_connected_users(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_user_count(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_buffer_sizes(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_selector_timeout(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_connection_timeout(AdminRequestParser *p, void *data);

RequestHandler admin_request_parser_user_total_concurrent_connections(AdminRequestParser *p, void *data);

#endif