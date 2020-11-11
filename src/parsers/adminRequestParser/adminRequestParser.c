
#include "parsers/adminRequestParser/adminRequestParser.h"
#include "parsers/adminRequestParser/adminRequestQueryHandlers.h"
#include "parsers/adminRequestParser/adminRequestModifierHandlers.h"
#include "parsers/adminRequestParser/adminRequestErrorHandlers.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static AdminRequestParserState admin_request_parser_get_arg_state_modifications(AdminRequestParserModification m);
static AdminRequestParserState admin_request_parser_get_arg_state_queries(AdminRequestParserQuery q);

static void (*admin_request_parser_get_query_handler(uint8_t b))(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);
static void (*admin_request_parser_get_modification_handler(uint8_t b))(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);

void admin_request_parser_init(AdminRequestParser *p){
    p->state = ARP_STATE_TYPE;
    p->type = 0xFF;
    p->command = 0xFF;
    p->parserCount = 0;
    p->argLength = -1;
    p->request_handler = admin_request_error_handler_invalid_type;
    memset(&p->args, '\0', sizeof(p->args));
}

bool admin_request_parser_consume(AdminRequestParser *p, Buffer *b, bool *errored){
    
    while(!admin_request_parser_is_done(p, errored) && buffer_can_read(b)){
        admin_request_parser_feed(p, buffer_read(b));
    }
    return admin_request_parser_is_done(p, errored);
}

AdminRequestParserState admin_request_parser_feed(AdminRequestParser *p, uint8_t b) {

    switch (p->state) {
        
        case ARP_STATE_TYPE:
            if(b == ARP_QUERY){
                p->type = b;
                p->state = ARP_STATE_QUERY;
            }
            else if(b == ARP_MODIFICATION){
                p->type = b;
                p->state = ARP_STATE_MODIFICATION;
            }
            else {
                p->request_handler = admin_request_error_handler_invalid_type;
                p->state = ARP_STATE_ERROR_TYPE_NOT_SUPPORTED;
            }
        break;

        case ARP_STATE_QUERY:
            p->command = b;
            p->request_handler = admin_request_parser_get_query_handler(p->command);
            p->state = admin_request_parser_get_arg_state_queries(p->command);
        break;

        case ARP_STATE_MODIFICATION:
            p->command = b;
            p->request_handler = admin_request_parser_get_modification_handler(p->command);
            p->state = admin_request_parser_get_arg_state_modifications(p->command);
        break;
        
        case ARP_PARSE_STRING:
        
            if(p->argLength == -1){
                p->parserCount = 0;
                p->argLength = b;   
            }

            else if(p->parserCount < p->argLength) {
                p->args.string[p->parserCount++] = b;
            }

            if(p->parserCount == p->argLength) {
                p->args.string[p->parserCount++] = '\0';
                p->state = ARP_STATE_DONE;
            }

        break;

        case ARP_PARSE_UINT_8:
        
            p->args.uint8 = b;
            
            p->state = ARP_STATE_DONE;

        break;

        case ARP_PARSE_UINT_32:

            if(p->argLength == -1){
                p->parserCount = 0;
                p->args.uint32 = 0;
                p->argLength = sizeof(uint32_t);
            }

            if(p->parserCount < p->argLength) {
                p->args.uint32 <<= 8;
                p->args.uint32 += b;
                p->parserCount++;
            }

            if(p->parserCount == p->argLength) {
                p->state = ARP_STATE_DONE;
            }
            
        break;

        case ARP_PARSE_ADD_USER:

             if(p->argLength == -1){
                p->parserCount = 0;
                p->argLength = b;
            }

            else if(p->parserCount < p->argLength) {
                p->args.user.uname[p->parserCount++] = b;
            }

            if(p->parserCount == p->argLength) {
                p->argLength = -1;
                p->args.user.uname[p->parserCount++] = '\0';
                p->state = ARP_PARSE_ADD_PASS;
            }
            
        break;

        case ARP_PARSE_ADD_PASS:
            
             if(p->argLength == -1){
                p->parserCount = 0;
                p->argLength = b;

            }

            else if(p->parserCount < p->argLength) {
                p->args.user.pass[p->parserCount++] = b;
            }

            if(p->parserCount == p->argLength) {
                p->args.user.pass[p->parserCount++] = '\0';
                p->state = ARP_PARSE_ADD_PRIV;
            }
            
        break;

        case ARP_PARSE_ADD_PRIV:
            
            p->args.user.admin = b;
            
            p->state = ARP_STATE_DONE;

        break;

        case ARP_STATE_DONE:

        break;

        default:
            p->state = ARP_ERROR_INVALID_STATE;
        break;
    }
    return p->state;
}

bool admin_request_parser_is_done(AdminRequestParser *p, bool *errored) {

    *errored = false;
    switch (p->state){
        
        case ARP_STATE_TYPE:
        case ARP_STATE_QUERY:
        case ARP_STATE_MODIFICATION:
        case ARP_PARSE_STRING:
        case ARP_PARSE_UINT_8:
        case ARP_PARSE_UINT_32:
        case ARP_PARSE_ADD_USER:
        case ARP_PARSE_ADD_PASS:
        case ARP_PARSE_ADD_PRIV:
            return false;

        case ARP_STATE_ERROR_TYPE_NOT_SUPPORTED:
        case ARP_STATE_ERROR_QUERY_NOT_SUPPORTED:
        case ARP_STATE_ERROR_MODIFICATION_NOT_SUPPORTED:
        case ARP_ERROR_NO_PARSER_STATE:
        case ARP_ERROR_INVALID_STATE:
            *errored = true;
            return true;

        case ARP_STATE_DONE:
            return true;

        default:
            *errored = true;
            return true;
    }
}

static AdminRequestParserState admin_request_parser_get_arg_state_modifications(AdminRequestParserModification m) {

    switch (m) {
         case ARP_ADD_USER:
            return ARP_PARSE_ADD_USER;
        break;
        case ARP_REMOVE_USER:
            return ARP_PARSE_STRING;
        break;

        case ARP_TOGGLE_PASSWORD_SPOOFING:
        case ARP_TOGGLE_CONNECTION_CLEAN_UN:
        case ARP_SET_SELECTOR_TIMEOUT:
        case ARP_SET_CONNECTION_TIMEOUT:
            return ARP_PARSE_UINT_8;
        break;

        case ARP_SET_BUFFER_SIZE:
            return ARP_PARSE_UINT_32;
        break;
            
    
    default:
        return ARP_STATE_ERROR_MODIFICATION_NOT_SUPPORTED;
    }
}

static AdminRequestParserState admin_request_parser_get_arg_state_queries(AdminRequestParserQuery q) {

    switch (q) {
        case ARP_LIST_USERS:
        case ARP_TOTAL_HISTORIC_CONNECTIONS:
        case ARP_CURRENT_CONNECTIONS:
        case ARP_MAX_CONCURRENT_CONECTIONS:
        case ARP_TOTAL_BYTES_SENT:
        case ARP_TOTAL_BYTES_RECEIVED:
        case ARP_CONNECTED_USERS:
        case ARP_TOTAL_USER_COUNT:
        case ARP_BUFFER_SIZES:
        case ARP_SELECTOR_TIMEOUT:
        case ARP_CONNECTION_TIMEOUT:
            return ARP_STATE_DONE;
        
        case ARP_USER_TOTAL_CURRENT_CONNECTIONS:
            return ARP_PARSE_STRING;
        
        default:
            return ARP_STATE_ERROR_QUERY_NOT_SUPPORTED;
    }
}

static void (*admin_request_parser_get_query_handler(uint8_t b))(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    switch (b){
        case ARP_LIST_USERS:
            return admin_request_parser_list_users;
            break;
        case ARP_TOTAL_HISTORIC_CONNECTIONS:
            return admin_request_parser_total_historic_connections;
            break;
        case ARP_CURRENT_CONNECTIONS:
            return admin_request_parser_current_connections;
            break;
        case ARP_MAX_CONCURRENT_CONECTIONS:
            return admin_request_parser_max_current_conections;
            break;
        case ARP_TOTAL_BYTES_SENT:
            return admin_request_parser_total_bytes_sent;
            break;
        case ARP_TOTAL_BYTES_RECEIVED:
            return admin_request_parser_total_bytes_received;
            break;
        case ARP_CONNECTED_USERS:
            return admin_request_parser_connected_users;
            break;
        case ARP_TOTAL_USER_COUNT:
            return admin_request_parser_total_user_count;
            break;
        case ARP_BUFFER_SIZES:
            return admin_request_parser_buffer_sizes;
            break;
        case ARP_SELECTOR_TIMEOUT:
            return admin_request_parser_selector_timeout;
            break;
        case ARP_CONNECTION_TIMEOUT:
            return admin_request_parser_connection_timeout;
        break;
        case ARP_USER_TOTAL_CURRENT_CONNECTIONS:
            return admin_request_parser_user_total_current_connections;
        break;
    
        default:
            return admin_request_error_handler_invalid_query;
        break;
    }
}

static void (*admin_request_parser_get_modification_handler(uint8_t b))(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer) {

    switch (b){
        case ARP_ADD_USER:
            return admin_request_parser_add_user;
            break;
        case ARP_REMOVE_USER:
            return admin_request_parser_remove_user;
            break;
        case ARP_TOGGLE_PASSWORD_SPOOFING:
            return admin_request_parser_toggle_password_spoofing;
            break;
        case ARP_TOGGLE_CONNECTION_CLEAN_UN:
            return admin_request_parser_toggle_connection_clean_up;
            break;
        case ARP_SET_BUFFER_SIZE:
            return admin_request_parser_set_buffer_size;
            break;
        case ARP_SET_SELECTOR_TIMEOUT:
            return admin_request_parser_set_selector_timeout;
            break;
        case ARP_SET_CONNECTION_TIMEOUT:
            return admin_request_parser_set_connection_timeout;
            break;
    
        default:
            return admin_request_error_handler_invalid_modification;
            break;
    }
}
