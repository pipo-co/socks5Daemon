#ifndef REQUEST_UTILITIES_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define REQUEST_UTILITIES_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socks5/socks5SessionDefinition.h"

typedef enum RequestUtilitiesSize {
    RU_DATE_SIZE                               = 30,
    RU_REPLY_SIZE                              = 10,
    RU_CREDENTIAL_MAX_SIZE                     = 255,
    RU_DOMAIN_NAME_MAX_LENGTH                  = 256,
} RequestUtilitiesSize;

void log_user_access(SessionHandlerP session, ReplyValues rep);

void log_credential_spoofing(SessionHandlerP session);

bool request_marshall(Buffer *b, size_t *bytes, ReplyValues rep);

ReplyValues request_get_reply_value_from_errno(int error);

#endif