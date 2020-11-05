#ifndef SOCKS_DEFS_H_cf4d27b2104418614ed38921062fe13b24a39d51
#define SOCKS_DEFS_H_cf4d27b2104418614ed38921062fe13b24a39d51

#define SOCKS_VERSION 0x05
#define AUTH_VERSION 0x01
#define AUTH_SUCCESS_MESSAGE 0x00
#define RESPONSE_SUCCESS_MESSAGE 0x00
#define AUTH_UNSUCCESSFUL_MESSAGE 0xFF
#define RSV 0x00
#define ATYP 0x01

#define DOMAIN_NAME_MAX_LENGTH 255
#define IP4_LENGTH 4
#define IP6_LENGTH 16 // 4 * 8 + 7

typedef enum AuthMethods {
    NO_AUTHENTICATION       = 0x00, 
    USER_PASSWORD           = 0x02,
    NO_ACCEPTABLE_METHODS   = 0xff,
} AuthMethods;

typedef enum Socks5AddressTypes { 
    SOCKS_5_ADD_TYPE_IP4            = 0x01, 
    SOCKS_5_ADD_TYPE_DOMAIN_NAME    = 0x03, 
    SOCKS_5_ADD_TYPE_IP6            = 0x04,
} Socks5AddressTypes;

typedef enum ReplyValues {
    SUCCESSFUL                          = 0x00,
    GENERAL_SOCKS_SERVER_FAILURE        = 0x01,
    CONNECTION_NOT_ALLOWED_BY_RULESET   = 0x02,
    NETWORK_UNREACHABLE                 = 0x03,
    HOST_UNREACHABLE                    = 0x04,
    CONNECTION_REFUSED                  = 0x05,
    TTL_EXPIRED                         = 0x06,
    COMMAND_NOT_SUPPORTED               = 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED          = 0x08,
} ReplyValues;

#endif
