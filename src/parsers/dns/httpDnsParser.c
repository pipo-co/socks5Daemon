#include "httpDnsParser.h"
#include "reference/parser_utils/parser_utils.h"

void http_dns_parser_init(HttpDnsParser *p) {

    struct parser_definition statusCodeParserDefinition;
    parser_utils_strcmpi(&statusCodeParserDefinition, "200 OK");
    // Ya se copio a la estructura todas las transiciones
    parser_init(&p->statusCodeParser, parser_no_classes(), &statusCodeParserDefinition);
    // Ya esta todo inicializado en memoria estatica
    

    struct parser_definition contentLengthParserDefinition;
    parser_utils_strcmpi(&contentLengthParserDefinition, "Content-Length: ");
    parser_init(&p->contentLengthParser, parser_no_classes(), &contentLengthParserDefinition);
    

    struct parser_definition payloadDelimiterParserDefinition;
    parser_utils_strcmpi(&payloadDelimiterParserDefinition, "\r\n\r\n");
    parser_init(&p->payloadDelimiterParser, parser_no_classes(), &payloadDelimiterParserDefinition);

    p->currentState = HTTP_STATUS_CODE_FIRST;
    p->contentLenght = 0;
    
}

enum HttpDnsParserState http_dns_parser_feed(HttpDnsParser *p, uint8_t b) {

    const struct parser_event * event;
    switch(p->currentState) {

        case HTTP_STATUS_CODE_FIRST:
            if(event = parser_feed(&p->statusCodeParser, b), event->type == STRING_CMP_NEQ){
                parser_reset(&p->statusCodeParser);
            }
            else if (event->type == STRING_CMP_EQ ){
                p->currentState = HTTP_CONTENT_LENGTH;
            }
                
        break;

        case HTTP_CONTENT_LENGTH:
            if(event = parser_feed(&p->contentLengthParser, b), event->type == STRING_CMP_NEQ){
                parser_reset(&p->contentLengthParser);
            }
            else if ( event->type == STRING_CMP_EQ ){
                p->currentState = HTTP_CONTENT_LENGTH_NUMBER;
            }
        

        break;

        case HTTP_CONTENT_LENGTH_NUMBER:
            if(b != '\r'){
                p->contentLenght = p->contentLenght * 10 + (b - '0');
            }
            else
            {
                 p->currentState = HTTP_CONTENT_LENGTH_FINISH;
            }
        
        break;

        case HTTP_CONTENT_LENGTH_FINISH:
            if(b != '\n'){
                p->currentState = HTTP_DNS_ERROR;
            }
            else{
                p->currentState = HTTP_SECOND_LINE;
            }
        
        break;

        case HTTP_SECOND_LINE:
            if(b != '\r'){
                p->currentState = HTTP_PAYLOAD_DELIMITER;
            }
            else
            {
                p->currentState = HTTP_LAST_CHARACTER;
            }
        
        break;

        case HTTP_LAST_CHARACTER:
            if(b != '\n'){
                p->currentState = HTTP_PAYLOAD_DELIMITER;
            }
            else
            {
                p->currentState = HTTP_DNS_DONE;
            }
        
        break;

        case HTTP_PAYLOAD_DELIMITER:
            if(event = parser_feed(&p->payloadDelimiterParser, b), event->type == STRING_CMP_NEQ){
                parser_reset(&p->payloadDelimiterParser);
            }
            else if ( event->type == STRING_CMP_EQ ){
                p->currentState = HTTP_DNS_DONE;
            }
            
                
        break;

        case HTTP_DNS_DONE:
        case HTTP_DNS_ERROR:
            //Nada que hacer
        break;

        default:
            p->currentState = HTTP_DNS_ERROR;
        break;
    }
    return p->currentState;
}

bool http_dns_parser_consume(Buffer *buffer, HttpDnsParser *p, bool *errored) {

    uint8_t byte;

    while(!http_dns_parser_is_done(p->currentState, errored) && buffer_can_read(buffer)) {
        
        byte = buffer_read(buffer);
        http_dns_parser_feed(p, byte); 
    }

    return http_dns_parser_is_done(p->currentState, errored);
}


bool http_dns_parser_is_done(enum HttpDnsParserState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {
        case HTTP_DNS_DONE:

            return true;
        break;

        case HTTP_STATUS_CODE_FIRST:
        case HTTP_CONTENT_LENGTH:
        case HTTP_CONTENT_LENGTH_NUMBER:
        case HTTP_CONTENT_LENGTH_FINISH:
        case HTTP_SECOND_LINE:
        case HTTP_LAST_CHARACTER:
        case HTTP_PAYLOAD_DELIMITER:
        
            return false;
        break;

        case HTTP_DNS_ERROR:
        default:
            if(errored != NULL)
                *errored = true;

            return true;
        break;
    }
}
