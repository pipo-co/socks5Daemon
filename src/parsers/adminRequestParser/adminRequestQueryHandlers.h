#ifndef ADMIN_REQUEST_QUERIES_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_QUERIES_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include "parsers/adminRequestParser/adminRequestParser.h"

void admin_request_parser_list_users(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_total_historic_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_current_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_max_current_conections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_total_bytes_sent(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_total_bytes_received(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_connected_users(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_total_user_count(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_buffer_sizes(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_selector_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_connection_timeout(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_user_total_current_connections(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

#endif