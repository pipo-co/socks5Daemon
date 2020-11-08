#include "parsers/adminRequestParser/adminRequestParser.h"
#include "parsers/adminRequestParser/adminRequestParserQueries.h"
#include "parsers/adminRequestParser/adminRequestParserModifiers.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

static AdminRequestParserState admin_request_parser_get_arg_state_modifications(AdminRequestParserModification m);
static AdminRequestParserState admin_request_parser_get_arg_state_queries(AdminRequestParserQuery q);
static RequestHandler admin_request_parser_get_query_handler(uint8_t b);
static RequestHandler admin_request_parser_get_modification_handler(uint8_t b);

void parser_init(AdminRequestParser *p){
    p->parserCount = 0;
    p->argLength = -1;  //Podria ser 0 ahora
}

bool admin_request_parser_consume(AdminRequestParser *p, Buffer *b){
    
    bool errored;
    while(admin_request_parser_is_done(p, &errored) && buffer_can_read(b)){
        admin_request_parser_feed(p, buffer_read(b));
    }
    return admin_request_parser_is_done(p, &errored);
}

AdminRequestParserState admin_request_parser_feed(AdminRequestParser *p, uint8_t b) {

    switch (p->state) {
        
        case ARP_STATE_TYPE:
            if(b == QUERY){
                p->type = b;
                return ARP_STATE_QUERY;
            }
            if(b == MODIFICATION){
                p->type = b;
                return ARP_STATE_MODIFICATION;
            }
            return ARP_STATE_ERROR_TYPE_NOT_SUPPORTED;
        break;

        case ARP_STATE_QUERY:
            p->command = b;
            p->requestHandler = admin_request_parser_get_query_handler(p->command);
            
            if(p->requestHandler == NULL){
                return ARP_STATE_ERROR_QUERY_NOT_SUPPORTED;
            }
            
            return admin_request_parser_get_arg_state_queries(p->command);
        break;

        case ARP_STATE_MODIFICATION:
            p->command = b;
            p->requestHandler = admin_request_parser_get_modification_handler(p->command);
            
            if(p->requestHandler == NULL){
                return ARP_STATE_ERROR_MODIFICATION_NOT_SUPPORTED;
            }
            
            return admin_request_parser_get_arg_state_modifications(p->command);
        break;
        
        case ARP_PARSE_STRING:
        
            if(p->argLength == -1){
                p->parserCount = 0;
                p->argLength = b;
                p->data = malloc(p->argLength + 1);
                
                if(p->data == NULL) {
                    return ARP_STATE_ERROR_NOT_ENOUGH_MEMORY;
                }
            }

            else if(p->parserCount < p->argLength) {
                ((uint8_t *)p->data)[p->parserCount++] = b;
            }

            if(p->parserCount == p->argLength) {
                ((uint8_t *)p->data)[p->parserCount++] = '\0';
                return ARP_STATE_DONE;
            }

            return ARP_PARSE_STRING;
        break;

        case ARP_PARSE_UINT_8:
        
            p->data = malloc(sizeof(uint8_t));
                
            if(p->data == NULL) {
                return ARP_STATE_ERROR_NOT_ENOUGH_MEMORY;
            }
            
            *((uint8_t *)p->data) = b;
            
            return ARP_STATE_DONE;

        break;

        case ARP_PARSE_UINT_32:

            if(p->argLength == -1){
                p->parserCount = 0;
                p->argLength = sizeof(uint32_t);
                p->data = malloc(p->argLength);
                
                if(p->data == NULL) {
                    return ARP_STATE_ERROR_NOT_ENOUGH_MEMORY;
                }
            }

            else if(p->parserCount < p->argLength) {
                *((uint32_t *)p->data) <<= 8;
                *((uint32_t *)p->data) += b;
            }

            if(p->parserCount == p->argLength) {
                return ARP_STATE_DONE;
            }

            return ARP_PARSE_UINT_32;
        break;

        case ARP_PARSE_ADD_USER:

             if(p->argLength == -1){
                p->parserCount = 0;
                p->argLength = b;
                p->data = malloc(p->argLength + 1);
                
                if(p->data == NULL) {
                    return ARP_STATE_ERROR_NOT_ENOUGH_MEMORY;
                }
            }

            else if(p->parserCount < p->argLength) {
                ((uint8_t *)p->data)[p->parserCount++] = b;
            }

            if(p->parserCount == p->argLength) {
                p->argLength = -1;
                ((uint8_t *)p->data)[p->parserCount++] = '\0';
                return ARP_PARSE_ADD_PASS;
            }

            return ARP_PARSE_ADD_USER;
        break;

        case ARP_PARSE_ADD_PASS:
            
             if(p->argLength == -1){
                p->argLength = p->parserCount + b;
                p->data = realloc(p->argLength, p->argLength + 1);
                
                if(p->data == NULL) {
                    return ARP_STATE_ERROR_NOT_ENOUGH_MEMORY;
                }
            }

            else if(p->parserCount < p->argLength) {
                ((uint8_t *)p->data)[p->parserCount++] = b;
            }

            if(p->parserCount == p->argLength) {
                ((uint8_t *)p->data)[p->parserCount++] = '\0';
                return ARP_PARSE_ADD_PRIV;
            }

            return ARP_PARSE_ADD_PASS;
        break;

        case ARP_PARSE_ADD_PRIV:
            
            ((uint8_t *)p->data)[p->parserCount++] = b;
            
            return ARP_STATE_DONE;

        break;

        default:
            return ARP_ERROR_INVALID_STATE;
        break;
    }
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
        case ARP_STATE_ERROR_NOT_ENOUGH_MEMORY:
            *errored = true;
        case ARP_STATE_DONE:
            return true;
        default:
            *errored = true;
            return true;
    }
}

static AdminRequestParserState admin_request_parser_get_arg_state_modifications(AdminRequestParserModification m) {

    switch (m) {
         case ADD_USER:
            return ARP_PARSE_ADD_USER;
        break;
        case REMOVE_USER:
            return ARP_PARSE_STRING;
        break;

        case TOGGLE_PASSWORD_SPOOFING:
        case TOGGLE_CONNECTION_CLEAN_UN:
        case SET_SELECTOR_TIMEOUT:
        case SET_CONNECTION_TIMEOUT:
            return ARP_PARSE_UINT_8;
        break;

        case SET_BUFFER_SIZE:
            return ARP_PARSE_UINT_32;
        break;
            
    
    default:
        break;
    }
}

static AdminRequestParserState admin_request_parser_get_arg_state_queries(AdminRequestParserQuery q) {

    switch (q) {
        case LIST_USERS:
        case TOTAL_HISTORIC_CONNECTIONS:
        case CURRENT_CONNECTIONS:
        case MAX_CURRENT_CONECTIONS:
        case TOTAL_BYTES_SENT:
        case TOTAL_BYTES_RECEIVED:
        case CONNECTED_USERS:
        case USER_COUNT:
        case BUFFER_SIZES:
        case SELECTOR_TIMEOUT:
        case CONNECTION_TIMEOUT:
            return ARP_STATE_DONE;
        
        case USER_TOTAL_CONCURRENT_CONNECTIONS:
            return ARP_PARSE_STRING;
        
        default:
            return ARP_ERROR_NO_PARSER_STATE;
    }
}

static RequestHandler admin_request_parser_get_query_handler(uint8_t b) {
    
    switch (b){
        case LIST_USERS:
            return admin_request_parser_list_users;
            break;
        case TOTAL_HISTORIC_CONNECTIONS:
            return admin_request_parser_total_historic_connections;
            break;
        case CURRENT_CONNECTIONS:
            return admin_request_parser_current_connections;
            break;
        case MAX_CURRENT_CONECTIONS:
            return admin_request_parser_max_current_conections;
            break;
        case TOTAL_BYTES_SENT:
            return admin_request_parser_total_bytes_sent;
            break;
        case TOTAL_BYTES_RECEIVED:
            return admin_request_parser_total_bytes_received;
            break;
        case CONNECTED_USERS:
            return admin_request_parser_connected_users;
            break;
        case USER_COUNT:
            return admin_request_parser_user_count;
            break;
        case BUFFER_SIZES:
            return admin_request_parser_buffer_sizes;
            break;
        case SELECTOR_TIMEOUT:
            return admin_request_parser_selector_timeout;
            break;
        case CONNECTION_TIMEOUT:
            return admin_request_parser_connection_timeout;
        break;
        case USER_TOTAL_CONCURRENT_CONNECTIONS:
            return admin_request_parser_user_total_concurrent_connections;
        break;
    
        default:
            return NULL;
        break;
    }
}

static RequestHandler admin_request_parser_get_modification_handler(uint8_t b) {

    switch (b){
        case ADD_USER:
            return admin_request_parser_add_user;
            break;
        case REMOVE_USER:
            return admin_request_parser_remove_user;
            break;
        case TOGGLE_PASSWORD_SPOOFING:
            return admin_request_parser_toggle_password_spoofing;
            break;
        case TOGGLE_CONNECTION_CLEAN_UN:
            return admin_request_parser_toggle_connection_clean_up;
            break;
        case SET_BUFFER_SIZE:
            return admin_request_parser_set_buffer_size;
            break;
        case SET_SELECTOR_TIMEOUT:
            return admin_request_parser_set_selector_timeout;
            break;
        case SET_CONNECTION_TIMEOUT:
            return admin_request_parser_set_connection_timeout;
            break;
    
        default:
            return NULL;
            break;
    }
}

