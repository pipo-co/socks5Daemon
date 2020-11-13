#include "spoofingParser.h"

#include <ctype.h>

typedef SpoofingParserState (*SpoofingParserStateFunction)(SpoofingParser*, SpoofingParserSenderType, uint8_t);

static SpoofingParserStateFunction spoofingStateFunctions[SP_FINISH + 1];

static bool spoofingIsParserLoaded = false;

static void spoofing_parser_load(void);
static inline SpoofingParserState spoofing_parser_spoof_byte(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static void spoofing_parser_init_string_parsers(SpoofingParser *parser, char* string1, char* string2);

// States
static SpoofingParserState spoofing_state_init(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// POP3
static SpoofingParserState spoofing_state_confirm_pop(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// Extracting User
static SpoofingParserState spoofing_state_pop_user_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_user_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_checking_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_extracting_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_checking_user_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// Extracting Pass
static SpoofingParserState spoofing_state_pop_pass_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_pass_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_checking_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_extracting_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pop_checking_pass_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// HTTP Spoofing
static SpoofingParserState spoofing_state_confirm_http(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_http_searching_auth(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_http_confirm_basic_scheme(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_http_extracting_credentials(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_http_client_confirmation_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_http_credential_confirmation(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);


static void spoofing_parser_load(void) {

    spoofingStateFunctions[SP_INIT]                             = spoofing_state_init;

    // POP3 Spoofing
    spoofingStateFunctions[SP_CONFIRM_POP]                      = spoofing_state_confirm_pop;

    // User Extraction
    spoofingStateFunctions[SP_POP_USER_SERVER_CONSUME]          = spoofing_state_pop_user_server_consume;
    spoofingStateFunctions[SP_POP_USER_CLIENT_CONSUME]          = spoofing_state_pop_user_client_consume;
    spoofingStateFunctions[SP_POP_CHECKING_USER]                = spoofing_state_pop_checking_user;
    spoofingStateFunctions[SP_POP_EXTRACTING_USER]              = spoofing_state_pop_extracting_user;
    spoofingStateFunctions[SP_POP_CHECKING_USER_RESPONSE]       = spoofing_state_pop_checking_user_response;

    // Pass Extraction
    spoofingStateFunctions[SP_POP_PASS_SERVER_CONSUME]          = spoofing_state_pop_pass_server_consume;
    spoofingStateFunctions[SP_POP_PASS_CLIENT_CONSUME]          = spoofing_state_pop_pass_client_consume;
    spoofingStateFunctions[SP_POP_CHECKING_PASS]                = spoofing_state_pop_checking_pass;
    spoofingStateFunctions[SP_POP_EXTRACTING_PASS]              = spoofing_state_pop_extracting_pass;
    spoofingStateFunctions[SP_POP_CHECKING_PASS_RESPONSE]       = spoofing_state_pop_checking_pass_response;

    // HTTP Spoofing
    spoofingStateFunctions[SP_CONFIRM_HTTP]                     = spoofing_state_confirm_http;
    spoofingStateFunctions[SP_HTTP_SEARCHING_AUTH]              = spoofing_state_http_searching_auth;
    spoofingStateFunctions[SP_HTTP_CONFIRM_BASIC_SCHEME]        = spoofing_state_http_confirm_basic_scheme;
    spoofingStateFunctions[SP_HTTP_EXTRACTING_CREDENTIALS]      = spoofing_state_http_extracting_credentials;
    spoofingStateFunctions[SP_HTTP_CLIENT_CONFIRMATION_CONSUME] = spoofing_state_http_client_confirmation_consume;
    spoofingStateFunctions[SP_HTTP_CREDENTIAL_CONFIRMATION]     = spoofing_state_http_credential_confirmation;
    

    spoofingIsParserLoaded = true;
}

void spoofing_parser_init(SpoofingParser *parser) {

    if(!spoofingIsParserLoaded) {
        spoofing_parser_load();
    }

    parser->currentState = SP_INIT;
    parser->success = false;
    parser->areStringParsersInitialized = false;
    parser->credentialIter = 0;
    parser->ignoreSpaces = false;
}

void spoofing_parser_spoof(SpoofingParser *parser, uint8_t *buffer, size_t bytes, SpoofingParserSenderType senderType) {

    for(size_t i = 0; i < bytes && !spoofing_parser_is_done(parser); i++) {
        parser->currentState = spoofing_parser_spoof_byte(parser, senderType, buffer[i]);
    }
}

static inline SpoofingParserState spoofing_parser_spoof_byte(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    return spoofingStateFunctions[parser->currentState](parser, senderType, byte);
}

inline bool spoofing_parser_is_done(SpoofingParser *parser) {
    return parser->currentState == SP_FINISH;
}

static void spoofing_parser_init_string_parsers(SpoofingParser *parser, char* string1, char* string2) {

    struct parser_definition pDefinition;

    parser_utils_strcmpi(&pDefinition, string1);

    parser_init(&parser->primaryStringParser, parser_no_classes(), &pDefinition);

    if(string2 != NULL) {
        
        parser_utils_strcmpi(&pDefinition, string2);

        parser_init(&parser->secondaryStringParser, parser_no_classes(), &pDefinition);
    }

    parser->areStringParsersInitialized = true;
}

static SpoofingParserState spoofing_state_init(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_CLIENT) {
        parser->currentState = SP_CONFIRM_HTTP;
    }

    else {
        parser->currentState = SP_CONFIRM_POP;
    }

    return spoofing_parser_spoof_byte(parser, senderType, byte);
}

static SpoofingParserState spoofing_state_confirm_pop(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_CLIENT || !__isascii(byte)) {
        return SP_FINISH;
    }

    if(!parser->areStringParsersInitialized) {

        spoofing_parser_init_string_parsers(parser, "+OK", NULL);
    }

    struct parser_event *event = parser_feed(&parser->primaryStringParser, byte);

    if(event->type == STRING_CMP_EQ) {

        parser->protocol = SPOOF_POP;
        parser->areStringParsersInitialized = false;
        return SP_POP_USER_SERVER_CONSUME;
    }

    // Not POP3
    else if(event->type == STRING_CMP_NEQ){
        return SP_FINISH;
    }

    else {
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_pop_user_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_SERVER) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_CHECKING_USER;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_pop_user_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_CLIENT) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_USER_SERVER_CONSUME;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_pop_checking_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(!__isascii(byte)) {
        return SP_FINISH;
    }

    if(senderType == SPOOF_SERVER) {
        parser->areStringParsersInitialized = false;
        return SP_POP_USER_SERVER_CONSUME;
    }

    if(!parser->areStringParsersInitialized) {
        
        spoofing_parser_init_string_parsers(parser, "USER ", NULL);
    }

    struct parser_event *event = parser_feed(&parser->primaryStringParser, byte);

    if(event->type == STRING_CMP_EQ) {

        parser->areStringParsersInitialized = false;
        return SP_POP_EXTRACTING_USER;
    }

    else if(event->type == STRING_CMP_NEQ) {

        parser->areStringParsersInitialized = false;
        return SP_POP_USER_CLIENT_CONSUME;
    }

    else {
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_pop_extracting_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_SERVER || !__isascii(byte)) {
        return SP_FINISH;
    }

    // Support CRLF and just LF
    if(byte == '\r') {
        return parser->currentState;
    }

    else if(byte == '\n') {

        parser->username[parser->credentialIter] = 0;
        parser->credentialIter = 0;
        return SP_POP_CHECKING_USER_RESPONSE;
    }

    else {

        parser->username[parser->credentialIter++] = (char) byte;
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_pop_checking_user_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Pipelining Detected
    if(senderType == SPOOF_CLIENT || !__isascii(byte)) {
        return SP_FINISH;
    }

    if(byte == '+') {
        return SP_POP_PASS_SERVER_CONSUME;
    }

    else if(byte == '-') {
        return SP_POP_USER_SERVER_CONSUME;
    }

    // Not POP3
    else {
        return SP_FINISH;
    }
}

static SpoofingParserState spoofing_state_pop_pass_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_SERVER) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_CHECKING_PASS;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_pop_pass_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_CLIENT) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_PASS_SERVER_CONSUME;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_pop_checking_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(!__isascii(byte)) {
        return SP_FINISH;
    }

    if(senderType == SPOOF_SERVER) {
        parser->areStringParsersInitialized = false;
        return SP_POP_PASS_SERVER_CONSUME;
    }

    if(!parser->areStringParsersInitialized) {
        
        spoofing_parser_init_string_parsers(parser, "PASS ", "USER ");
    }

    struct parser_event *passEvent = parser_feed(&parser->primaryStringParser, byte);
    struct parser_event *userEvent = parser_feed(&parser->secondaryStringParser, byte);

    if(passEvent->type == STRING_CMP_EQ) {

        parser->areStringParsersInitialized = false;
        return SP_POP_EXTRACTING_PASS;
    }

    else if(userEvent->type == STRING_CMP_EQ) {

        parser->areStringParsersInitialized = false;
        return SP_POP_EXTRACTING_USER;
    }

    else if(passEvent->type == STRING_CMP_NEQ && userEvent->type == STRING_CMP_NEQ) {

        parser->areStringParsersInitialized = false;
        return SP_POP_PASS_CLIENT_CONSUME;
    }

    else {
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_pop_extracting_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_SERVER || !__isascii(byte)) {
        return SP_FINISH;
    }

    // Support CRLF and just LF
    if(byte == '\r') {
        return parser->currentState;
    }

    else if(byte == '\n') {

        parser->password[parser->credentialIter] = 0;
        parser->credentialIter = 0;
        return SP_POP_CHECKING_PASS_RESPONSE;
    }

    else {

        parser->password[parser->credentialIter++] = (char) byte;
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_pop_checking_pass_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Pipelining Detected
    if(senderType == SPOOF_CLIENT || !__isascii(byte)) {
        return SP_FINISH;
    }

    // POP3 Credentials Sniffed! 
    if(byte == '+') {

        parser->success = true;
        return SP_FINISH;
    }

    // Invalid User and Pass Combination
    else if(byte == '-') {
        return SP_POP_USER_SERVER_CONSUME;
    }

    // Not POP3
    else {
        return SP_FINISH;
    }
}

static SpoofingParserState spoofing_state_confirm_http(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not HTTP
    if(senderType == SPOOF_SERVER || !__isascii(byte)) {
        return SP_FINISH;
    }

    if(!parser->areStringParsersInitialized) {

        // Supporting HTTP 1.0 and 1.1
        spoofing_parser_init_string_parsers(parser, "HTTP/1.", NULL);
    }

    // Not HTTP. No detectamos el header HTTP/1.* en la primera linea de los headers
    if(byte == '\n') {
        return SP_FINISH;
    }

    struct parser_event *event = parser_feed(&parser->primaryStringParser, byte);

    if(event->type == STRING_CMP_EQ) {

        parser->protocol = SPOOF_HTTP;
        parser->areStringParsersInitialized = false;
        return SP_HTTP_SEARCHING_AUTH;
    }

    else if(event->type == STRING_CMP_NEQ) {

        parser_reset(&parser->primaryStringParser);
        return parser->currentState;
    }

    else {
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_http_searching_auth(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not HTTP or Error. Auth is not present in server messages. 
    // CRLFCRLF (header ending) must reach before server response
    if(senderType == SPOOF_SERVER || !__isascii(byte)) {
        return SP_FINISH;
    }

    if(!parser->areStringParsersInitialized) {

        spoofing_parser_init_string_parsers(parser, "Authorization: ", "\r\n\r\n"); // CRLFCRLF
    }

    struct parser_event *foundEvent = parser_feed(&parser->primaryStringParser, byte);
    struct parser_event *notFoundEvent = parser_feed(&parser->secondaryStringParser, byte);

    // Authorixation found
    if(foundEvent->type == STRING_CMP_EQ) {

        parser->areStringParsersInitialized = false;
        parser->ignoreSpaces = true;
        return SP_HTTP_CONFIRM_BASIC_SCHEME;
    }

    // Authorization not found on first header
    else if(notFoundEvent->type == STRING_CMP_EQ) {
        return SP_FINISH;
    }

    // Keep looking for Auth until a parser matches or the server sends a response (error)
    if(foundEvent->type == STRING_CMP_NEQ) {

        parser_reset(&parser->primaryStringParser);
    }

    if(notFoundEvent->type == STRING_CMP_NEQ) {

        parser_reset(&parser->secondaryStringParser);
    }

    return parser->currentState;
}

static SpoofingParserState spoofing_state_http_confirm_basic_scheme(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not HTTP or Error. CRLFCRLF (header ending) must reach before server response
    if(senderType == SPOOF_SERVER || !__isascii(byte)) {
        return SP_FINISH;
    }

    // Ignore leading spaces
    if(parser->ignoreSpaces && isblank(byte)) {
        return parser->currentState;
    }

    if(parser->ignoreSpaces && !isblank(byte)) {
        parser->ignoreSpaces = false;
    }

    if(!parser->areStringParsersInitialized) {

        // Supporting HTTP 1.0 and 1.1
        spoofing_parser_init_string_parsers(parser, "Basic ", NULL);
    }

    struct parser_event *event = parser_feed(&parser->primaryStringParser, byte);

    if(event->type == STRING_CMP_EQ) {

        parser->areStringParsersInitialized = false;
        parser->ignoreSpaces = true;
        return SP_HTTP_EXTRACTING_CREDENTIALS;
    }

    // Cannot Spoof. 
    // Basic not found in authorization header, the only scheme supported
    // Note: Authorization headers only support one scheme
    else if(event->type == STRING_CMP_NEQ) {
        return SP_FINISH;
    }

    else {
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_http_extracting_credentials(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not HTTP or Error. CRLFCRLF (header ending) must reach before server response
    if(senderType == SPOOF_SERVER || !__isascii(byte)) {
        return SP_FINISH;
    }

    // Ignore leading spaces
    if(parser->ignoreSpaces && isblank(byte)) {
        return parser->currentState;
    }

    if(parser->ignoreSpaces && !isblank(byte)) {
        parser->ignoreSpaces = false;
    }

    // Finish Extracting
    if(byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r') {

        parser->base64Credentials[parser->credentialIter] = 0;

        // Decode Credentials
        size_t len = base64_decode(parser->base64Credentials, (uint8_t*) parser->base64Credentials);

        // Copy decoded base64 to username and password (separated by :)
        size_t i;

        // Copy username until :
        for(i = 0; i < len && parser->base64Credentials[i] != ':'; i++) {

            parser->username[i] = parser->base64Credentials[i];
        }

        parser->username[i] = 0;

        size_t offset = i + 1;

        len -= offset;

        // Copy rest to password
        for(i = 0; i < len; i++) {

            parser->password[i] = parser->base64Credentials[i + offset];
        }

        parser->password[i] = 0;

        parser->ignoreSpaces = false;
        parser->credentialIter = 0;
        return SP_HTTP_CLIENT_CONFIRMATION_CONSUME;
    }

    // Is valid base64 char
    else if(isalnum(byte) || byte == '+' || byte == '/' || byte == '=') {

        parser->base64Credentials[parser->credentialIter++] = (char) byte;
        return parser->currentState;
    }

    // Not a valid base64 char - Error
    else {
        return SP_FINISH;
    }
}

static SpoofingParserState spoofing_state_http_client_confirmation_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_CLIENT) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_HTTP_CREDENTIAL_CONFIRMATION;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_http_credential_confirmation(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not HTTP or Error. Unexpected Client Message
    if(senderType == SPOOF_CLIENT || !__isascii(byte)) {
        return SP_FINISH;
    }

    if(!parser->areStringParsersInitialized) {

        spoofing_parser_init_string_parsers(parser, "HTTP/1.1 2", "HTTP/1.0 2");
    }

    struct parser_event *event1 = parser_feed(&parser->primaryStringParser, byte);
    struct parser_event *event0 = parser_feed(&parser->secondaryStringParser, byte);

    // Server Confirmed Credentials!
    if(event1->type == STRING_CMP_EQ || event0->type == STRING_CMP_EQ) {

        parser->areStringParsersInitialized = false;
        parser->success = true;
        return SP_FINISH;
    }

    // Invalid Credentials :(
    else if(event1->type == STRING_CMP_NEQ && event0->type == STRING_CMP_NEQ) {
        return SP_FINISH;
    }

    else {
        return parser->currentState;
    }
}

