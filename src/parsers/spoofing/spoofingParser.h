#ifndef SPOOFING_PARSER_H_237cf11b918a97e16402b064e7e5af5cd7f70661
#define SPOOFING_PARSER_H_237cf11b918a97e16402b064e7e5af5cd7f70661

#include "utilities/base64/base64.h"
#include "reference/parser_utils/parser_utils.h"


/*
* HTTP 1.0 supported
* POP3 without pipelining supported
*/

// Credentials longer than this number are not supported
#define MAX_CREDENTIAL_SIZE 255

typedef enum SpoofingParserState {
    SP_INIT,

    // HTTP 1.0 Spoofing
    SP_CONFIRM_HTTP,
    SP_HTTP_SEARCHING_AUTH,
    SP_HTTP_CONFIRM_BASIC_SCHEME,
    SP_HTTP_EXTRACTING_CREDENTIALS,
    SP_HTTP_CLIENT_CONFIRMATION_CONSUME,
    SP_HTTP_CREDENTIAL_CONFIRMATION,

    // POP3 Spoofing
    SP_CONFIRM_POP,

    // User Extraction
    SP_POP_USER_SERVER_CONSUME,
    SP_POP_USER_CLIENT_CONSUME,
    SP_POP_CHECKING_USER,
    SP_POP_EXTRACTING_USER,
    SP_POP_CHECKING_USER_RESPONSE,

    // Pass Extraction
    SP_POP_PASS_SERVER_CONSUME,
    SP_POP_PASS_CLIENT_CONSUME,
    SP_POP_CHECKING_PASS,
    SP_POP_EXTRACTING_PASS,
    SP_POP_CHECKING_PASS_RESPONSE,

    SP_FINISH,
} SpoofingParserState;

typedef enum SpoofingParserSenderType {
    SPOOF_CLIENT,
    SPOOF_SERVER,
} SpoofingParserSenderType;

typedef enum SpoofingProtocol {
    SPOOF_POP,
    SPOOF_HTTP,
} SpoofingProtocol;


typedef struct SpoofingParser {

    SpoofingParserState currentState;

    bool success;

    SpoofingProtocol protocol;

    char username[MAX_CREDENTIAL_SIZE + 1];

    char password[MAX_CREDENTIAL_SIZE + 1];

// ---- PRIVATE ----

    char base64Credentials[BASE64_ENCODE_SIZE(2*(MAX_CREDENTIAL_SIZE + 1))];

    bool areStringParsersInitialized;

    struct parser primaryStringParser;

    struct parser secondaryStringParser;

    uint16_t credentialIter;

    bool ignoreSpaces;

} SpoofingParser;


void spoofing_parser_init(SpoofingParser *parser);

void spoofing_parser_spoof(SpoofingParser *parser, uint8_t *buffer, size_t bytes, SpoofingParserSenderType senderType);

bool spoofing_parser_is_done(SpoofingParser *parser);

#endif