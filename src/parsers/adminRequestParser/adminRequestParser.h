#ifndef ADMIN_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define ADMIN_REQUEST_PARSER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "buffer/buffer.h"

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
    ARP_STATE_ERROR_NOT_ENOUGH_MEMORY,
} AdminRequestParserState;

typedef enum AdminRequestParserType {
    QUERY               = 0x00,
    MODIFICATION        = 0x01,
} AdminRequestParserType;

typedef enum AdminRequestParserQuery {
    LIST_USERS                              = 0x00,
    TOTAL_HISTORIC_CONNECTIONS              = 0x01,
    CURRENT_CONNECTIONS                     = 0x02,
    MAX_CURRENT_CONECTIONS                  = 0x03,
    TOTAL_BYTES_SENT                        = 0x04,
    TOTAL_BYTES_RECEIVED                    = 0x05,
    CONNECTED_USERS                         = 0x06,
    USER_COUNT                              = 0x07,
    BUFFER_SIZES                            = 0x08,
    SELECTOR_TIMEOUT                        = 0x09,
    CONNECTION_TIMEOUT                      = 0x0A,
    USER_TOTAL_CONCURRENT_CONNECTIONS       = 0x0B,
} AdminRequestParserQuery;

typedef enum AdminRequestParserModification {
    ADD_USER                                = 0x00,
    REMOVE_USER                             = 0x01,
    TOGGLE_PASSWORD_SPOOFING                = 0x02,
    TOGGLE_CONNECTION_CLEAN_UN              = 0x03,
    SET_BUFFER_SIZE                         = 0x04,
    SET_SELECTOR_TIMEOUT                    = 0x05,
    SET_CONNECTION_TIMEOUT                  = 0x06,
} AdminRequestParserModification;

typedef bool (*RequestHandler)(struct AdminRequestParser *, Buffer *);

typedef struct AdminRequestParserUserInfo{
    uint8_t     uname[MAX_STRING_LENGTH];
    uint8_t     pass[MAX_STRING_LENGTH];
    uint8_t     admin;
} AdminRequestParserUserInfo;

typedef union AdminRequestParserArgs{
    uint8_t                     uint8;
    uint32_t                    uint32;
    uint8_t                     string[MAX_STRING_LENGTH];
    AdminRequestParserUserInfo  user;
} AdminRequestParserArgs; 

typedef struct AdminRequestParser {
    AdminRequestParserState     state;
    AdminRequestParserType      type; //Puede fletarse
    uint8_t                     command;
    int                         parserCount;    // i
    int                         argLength;      // n
    RequestHandler              requestHandler;
    AdminRequestParserArgs      args;
              //refactor to arg
} AdminRequestParser;

void parser_init(AdminRequestParser *p);

bool admin_request_parser_consume(AdminRequestParser *p, Buffer *b);

AdminRequestParserState admin_request_parser_feed(AdminRequestParser *p, uint8_t b);

bool admin_request_parser_is_done(AdminRequestParser *p, bool *errored);

#endif