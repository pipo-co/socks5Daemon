#ifndef REQUEST_UTILITIES_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define REQUEST_UTILITIES_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "socksDefs.h"
#include "socks5/socks5SessionDefinition.h"

void log_user_access(SessionHandlerP session, ReplyValues rep);

void log_credential_spoofing(SessionHandlerP session);

bool request_marshall(Buffer *b, size_t *bytes, ReplyValues rep);

ReplyValues request_get_reply_value_from_errno(int error);

#endif