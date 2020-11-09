#ifndef CLIENT_DEFS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_DEFS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

typedef enum ClientType {
    CT_QUERY               = 0x00,
    CT_MODIFICATION        = 0x01,
    CT_INVALID_TYPE        = 0xFF,
} ClientType;

// ClientTypeCommandCount
#define CTCC_QUERY_COUNT 12
#define CTCC_MODIFICATIONS_COUNT 7
#define COMMAND_COUNT (CTCC_QUERY_COUNT + CTCC_MODIFICATIONS_COUNT)

#define UINT8_BASE_10_SIZE 4
#define UINT32_BASE_10_SIZE 11

typedef enum ClientQuery {
    CQ_LIST_USERS                              = 0x00,
    CQ_TOTAL_HISTORIC_CONNECTIONS              = 0x01,
    CQ_CURRENT_CONNECTIONS                     = 0x02,
    CQ_MAX_CURRENT_CONECTIONS                  = 0x03,
    CQ_TOTAL_BYTES_SENT                        = 0x04,
    CQ_TOTAL_BYTES_RECEIVED                    = 0x05,
    CQ_CONNECTED_USERS                         = 0x06,
    CQ_USER_COUNT                              = 0x07,
    CQ_BUFFER_SIZES                            = 0x08,
    CQ_SELECTOR_TIMEOUT                        = 0x09,
    CQ_CONNECTION_TIMEOUT                      = 0x0A,
    CQ_USER_TOTAL_CONCURRENT_CONNECTIONS       = 0x0B,
    CQ_INVALID_PARAM                           = 0xFE,
    CQ_INVALID_QUERY                           = 0xFF,
} ClientQuery;

typedef enum ClientModification {
    CM_ADD_USER                                = 0x00,
    CM_REMOVE_USER                             = 0x01,
    CM_TOGGLE_PASSWORD_SPOOFING                = 0x02,
    CM_TOGGLE_CONNECTION_CLEAN_UN              = 0x03,
    CM_SET_BUFFER_SIZE                         = 0x04,
    CM_SET_SELECTOR_TIMEOUT                    = 0x05,
    CM_SET_CONNECTION_TIMEOUT                  = 0x06,
    CM_INVALID_MODIFICATION                    = 0xFF,
} ClientModification;

#endif
