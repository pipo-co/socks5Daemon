#ifndef ADMIN_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "buffer/buffer.h"
#include "adminResponseBuilder.h"

#define MAX_STRING_LENGTH 256

typedef enum AdminRequestParserState {
    ARP_STATE_TYPE,
    ARP_STATE_QUERY,
    ARP_STATE_MODIFICATION,

    ARP_PARSE_STRING,
    ARP_PARSE_UINT_8,
    ARP_PARSE_UINT_32,
    ARP_PARSE_ADD_USER,
    ARP_PARSE_ADD_PASS,
    ARP_PARSE_ADD_PRIV,
    
    ARP_STATE_DONE,

    ARP_STATE_ERROR_TYPE_NOT_SUPPORTED,
    ARP_STATE_ERROR_QUERY_NOT_SUPPORTED,
    ARP_STATE_ERROR_MODIFICATION_NOT_SUPPORTED,
    ARP_ERROR_NO_PARSER_STATE,
    ARP_ERROR_INVALID_STATE,
} AdminRequestParserState;

typedef enum AdminRequestParserType {
    ARP_QUERY               = 0x00,
    ARP_MODIFICATION        = 0x01,
    ARP_INVALID_TYPE        = 0xFF,
} AdminRequestParserType;

typedef enum AdminRequestParserQuery {
    ARP_LIST_USERS                                  = 0x00,
    ARP_TOTAL_HISTORIC_CONNECTIONS                  = 0x01,
    ARP_CURRENT_CONNECTIONS                         = 0x02,
    ARP_MAX_CONCURRENT_CONECTIONS                   = 0x03,
    ARP_TOTAL_BYTES_SENT                            = 0x04,
    ARP_TOTAL_BYTES_RECEIVED                        = 0x05,
    ARP_CONNECTED_USERS                             = 0x06,
    ARP_TOTAL_USER_COUNT                            = 0x07,
    ARP_BUFFER_SIZES                                = 0x08,
    ARP_SELECTOR_TIMEOUT                            = 0x09,
    ARP_CONNECTION_TIMEOUT                          = 0x0A,
    ARP_USER_TOTAL_CURRENT_CONNECTIONS              = 0x0B,
    ARP_INVALID_PARAM                               = 0xFE,
    ARP_INVALID_QUERY                               = 0xFF,

} AdminRequestParserQuery;

typedef enum AdminRequestParserModification {
    ARP_ADD_USER                                = 0x00,
    ARP_REMOVE_USER                             = 0x01,
    ARP_TOGGLE_PASSWORD_SPOOFING                = 0x02,
    ARP_TOGGLE_CONNECTION_CLEAN_UN              = 0x03,
    ARP_SET_BUFFER_SIZE                         = 0x04,
    ARP_SET_SELECTOR_TIMEOUT                    = 0x05,
    ARP_SET_CONNECTION_TIMEOUT                  = 0x06,
    ARP_INVALID_MODIFICATION                    = 0xFF,
} AdminRequestParserModification;

typedef struct AdminRequestParserUserInfo{
    char     uname[MAX_STRING_LENGTH];
    char     pass[MAX_STRING_LENGTH];
    uint8_t     admin;
} AdminRequestParserUserInfo;

typedef union AdminRequestParserArgs{
    uint8_t                     uint8;
    uint32_t                    uint32;
    char                     string[MAX_STRING_LENGTH];
    AdminRequestParserUserInfo  user;
} AdminRequestParserArgs; 

typedef struct AdminRequestParser {
    AdminRequestParserState         state;
    AdminRequestParserType          type;
    uint8_t                         command;
    int                             parserCount;    // i
    int                             argLength;      // n
    void (*request_handler)(uint8_t type, uint8_t cmd, AdminRequestParserArgs *args, AdminResponseBuilderContainer *outContainer);
    AdminRequestParserArgs          args;
} AdminRequestParser;

void admin_request_parser_init(AdminRequestParser *p);

bool admin_request_parser_consume(AdminRequestParser *p, Buffer *b, bool *errored);

AdminRequestParserState admin_request_parser_feed(AdminRequestParser *p, uint8_t b);

bool admin_request_parser_is_done(AdminRequestParser *p, bool *errored);

#endif