#include "spoofingParser.h"

typedef SpoofingParserState (*SpoofingParserStateFunction)(SpoofingParser*, SpoofingParserSenderType, uint8_t);

static SpoofingParserStateFunction stateFunctions[SP_FINISH + 1];

static bool isParserLoaded = false;

static void spoofing_parser_load(void);
static inline SpoofingParserState spoofing_parser_spoof_byte(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static void spoofing_parser_init_string_parsers(SpoofingParser *parser, char* string1, char* string2);

// States
static SpoofingParserState spoofing_state_init(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// POP3
static SpoofingParserState spoofing_state_confirm_pop(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// Extracting User
static SpoofingParserState spoofing_state_user_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_user_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_checking_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_extracting_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_checking_user_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);

// Extracting Pass
static SpoofingParserState spoofing_state_pass_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_pass_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_checking_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_extracting_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);
static SpoofingParserState spoofing_state_checking_pass_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte);


static void spoofing_parser_load(void) {

    stateFunctions[SP_INIT]                         = spoofing_state_init;

    // POP3 Spoofing
    stateFunctions[SP_CONFIRM_POP]                  = spoofing_state_confirm_pop;

    // User Extraction
    stateFunctions[SP_POP_USER_SERVER_CONSUME]      = spoofing_state_user_server_consume;
    stateFunctions[SP_POP_USER_CLIENT_CONSUME]      = spoofing_state_user_client_consume;
    stateFunctions[SP_POP_CHECKING_USER]            = spoofing_state_checking_user;
    stateFunctions[SP_POP_EXTRACTING_USER]          = spoofing_state_extracting_user;
    stateFunctions[SP_POP_CHECKING_USER_RESPONSE]   = spoofing_state_checking_user_response;

    // Pass Extraction
    stateFunctions[SP_POP_PASS_SERVER_CONSUME]      = spoofing_state_pass_server_consume;
    stateFunctions[SP_POP_PASS_CLIENT_CONSUME]      = spoofing_state_pass_client_consume;
    stateFunctions[SP_POP_CHECKING_PASS]            = spoofing_state_checking_pass;
    stateFunctions[SP_POP_EXTRACTING_PASS]          = spoofing_state_extracting_pass;
    stateFunctions[SP_POP_CHECKING_PASS_RESPONSE]   = spoofing_state_checking_pass_response;

    isParserLoaded = true;
}

void spoofing_parser_init(SpoofingParser *parser) {

    if(!isParserLoaded) {
        spoofing_parser_load();
    }

    parser->currentState = SP_INIT;
    parser->success = false;
    parser->areStringParsersInitialized = false;
    parser->credentialIter = 0;
}

void spoofing_parser_spoof(SpoofingParser *parser, uint8_t *buffer, size_t bytes, SpoofingParserSenderType senderType) {

    for(size_t i = 0; i < bytes && !spoofing_parser_is_done(parser); i++) {
        parser->currentState = spoofing_parser_spoof_byte(parser, senderType, buffer[i]);
    }
}

static inline SpoofingParserState spoofing_parser_spoof_byte(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    return stateFunctions[parser->currentState](parser, senderType, byte);
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

    if(senderType == SPOOF_CLIENT) {
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

static SpoofingParserState spoofing_state_user_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_SERVER) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_CHECKING_USER;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_user_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_CLIENT) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_USER_SERVER_CONSUME;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_checking_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

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

static SpoofingParserState spoofing_state_extracting_user(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_SERVER) {
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

static SpoofingParserState spoofing_state_checking_user_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_CLIENT) {
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

static SpoofingParserState spoofing_state_pass_server_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_SERVER) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_CHECKING_PASS;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_pass_client_consume(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    if(senderType == SPOOF_CLIENT) {
        return parser->currentState;
    }

    else {
        parser->currentState = SP_POP_PASS_SERVER_CONSUME;
        return spoofing_parser_spoof_byte(parser, senderType, byte);
    }
}

static SpoofingParserState spoofing_state_checking_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

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
        return SP_POP_USER_CLIENT_CONSUME;
    }

    else {
        return parser->currentState;
    }
}

static SpoofingParserState spoofing_state_extracting_pass(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_SERVER) {
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

static SpoofingParserState spoofing_state_checking_pass_response(SpoofingParser *parser, SpoofingParserSenderType senderType, uint8_t byte) {

    // Not POP3
    if(senderType == SPOOF_CLIENT) {
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