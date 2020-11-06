#include <stdio.h>
#include <stdlib.h>

#include "dnsParser.h"

void response_dns_parser_init(ResponseDnsParser *p) {

    p->currentState = RESPONSE_DNS_TRANSACTION_STATE;
    p->addresses = NULL;
    p->totalQuestions = 0;
    p->totalAnswers = 0;
    p->currentAnswers = 0;
    p->bytesWritten = 0;
    p->currentType = 0;
    p->counter = 0;
}

enum ResponseDnsParserState response_dns_parser_feed(ResponseDnsParser *p, uint8_t b) {

    switch(p->currentState) {

        case RESPONSE_DNS_TRANSACTION_STATE:
            if(p->bytesWritten == 0){
                p->bytesWritten++;
            }
            else{
                p->bytesWritten = 0;
                p->currentState = RESPONSE_DNS_FLAGS_STATE;
            }
            
        break;

        case RESPONSE_DNS_FLAGS_STATE:

            if(p->bytesWritten == 0){
                p->bytesWritten++;
            }
            else{
                p->bytesWritten = 0;
                p->currentState = RESPONSE_DNS_QUESTIONS_HIGH;
            }

        break;

        case RESPONSE_DNS_QUESTIONS_HIGH:
           
            p->totalQuestions = b << 8;

            p->currentState = RESPONSE_DNS_QUESTIONS_LOW;
        break;

        case RESPONSE_DNS_QUESTIONS_LOW:

            p->totalQuestions += b;
            p->currentState = RESPONSE_DNS_ANSWERS_HIGH;
            
        break;

        case RESPONSE_DNS_ANSWERS_HIGH:
            
            p->totalAnswers = b << 8;
            p->currentState = RESPONSE_DNS_ANSWERS_LOW;

        break;

        case RESPONSE_DNS_ANSWERS_LOW:
            
            p->totalAnswers += b;
            p->addresses = calloc(p->totalAnswers, sizeof(struct IpAddress));
            p->currentState = RESPONSE_DNS_AUTHORITY;

        break;
        case RESPONSE_DNS_AUTHORITY:
            
            if(p->bytesWritten == 0){
                p->bytesWritten++;
            }
            else{
                p->bytesWritten = 0;
                p->currentState = RESPONSE_DNS_ADITIONAL;
            }

        break;
        case RESPONSE_DNS_ADITIONAL:
            
            if(p->bytesWritten == 0){
                p->bytesWritten++;
            }
            else{
                p->bytesWritten = 0;
                p->currentState = RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE;
            }

        break;

        case RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE:
            
            if ((b & 0xC0) == 0xC0){
                p->currentState = RESPONSE_DNS_QUERIES_NAME_REFERENCE_SECOND_BYTE;
            }
            else if (b == 0){
                p->currentState = RESPONSE_DNS_QUERIES_TYPE;
            }
            else{
                p->bytesWritten = b;
                p->currentState = RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES;
            }

        break;

        case RESPONSE_DNS_QUERIES_NAME_REFERENCE_SECOND_BYTE:
            p->currentState = RESPONSE_DNS_QUERIES_TYPE;

        break;

        case RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES:
            p->bytesWritten--;

            if (p->bytesWritten == 0){
                p->currentState = RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE;
            }

        break;


        case RESPONSE_DNS_QUERIES_TYPE:

             if(p->bytesWritten == 0){
                p->bytesWritten++;
            }
            else{
                p->bytesWritten = 0;
                p->currentState = RESPONSE_DNS_QUERIES_CLASS;
            }
            
        break;
        case RESPONSE_DNS_QUERIES_CLASS:
            if(p->bytesWritten == 0){
                    p->bytesWritten++;
            }
            else{
                p->bytesWritten = 0;
                // p->totalQuestions--;

                // if(p->totalQuestions != 0){
                //     p->currentState = RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE;
                // }
                // else
                // {
                    p->currentState = RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE;
                // }
            }

        break;
        case RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE:
            if ((b & 0xC0) == 0xC0){
                p->currentState = RESPONSE_DNS_REFERENCE_SECOND_BYTE;
            }
            else if (b == 0){
                p->currentState = RESPONSE_DNS_ANSWERS_TYPE_HIGH;
            }
            else{
                p->bytesWritten = b;
                p->currentState = RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES;
            }

        break;

        case RESPONSE_DNS_REFERENCE_SECOND_BYTE:
            p->bytesWritten = 0;
            p->currentState = RESPONSE_DNS_ANSWERS_TYPE_HIGH;

        break;

        case RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES:
            p->bytesWritten--;

            if (p->bytesWritten == 0){
                p->currentState = RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE;
            }

        break;
        case RESPONSE_DNS_ANSWERS_TYPE_HIGH:
            
            p->currentType = b << 8;

            p->currentState = RESPONSE_DNS_ANSWERS_TYPE_LOW;
            
        break;

        case RESPONSE_DNS_ANSWERS_TYPE_LOW:

            p->currentType += b;
            p->currentState = RESPONSE_DNS_ANSWERS_CLASS;
            
        break;

        case RESPONSE_DNS_ANSWERS_CLASS:
            
            if(p->bytesWritten == 0){
                p->bytesWritten++;
            }
            else{
                p->bytesWritten=0;
                p->currentState = RESPONSE_DNS_ANSWERS_TTL;
            }
            
        break;

        case RESPONSE_DNS_ANSWERS_TTL:
            
            if(p->bytesWritten == 3){
                p->currentState = RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH;
                
            }
            else{
                p->bytesWritten++;
            }
            
        break;

        case RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH:
            
            p->dataLenght = b << 8;

            p->currentState = RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW;
            
        break;

        case RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW:
            
            p->dataLenght += b;
            
            if(p->dataLenght == 4){
                if(p->currentType == A){
                    
                    p->addresses[p->currentAnswers].ipType = IPV4;
                    p->counter = 4;
                    p->currentState = RESPONSE_DNS_IPV4_ADDRESS;
                }
                else
                {
                    p->totalAnswers--;
                    p->currentState = RESPONSE_DNS_CNAME;
                }   
            }
            else if (p->dataLenght == 16){
                if(p->currentType == AAAA){
    
                    p->addresses[p->currentAnswers].ipType = IPV6;
                    p->counter = p->dataLenght;
                    p->currentState = RESPONSE_DNS_IPV6_ADDRESS;
                }
                else
                {
                    p->totalAnswers--;
                    p->currentState = RESPONSE_DNS_CNAME;
                }   
            }
            else
            {
                p->totalAnswers--;
                p->currentState = RESPONSE_DNS_CNAME;
            }
        break;

        case RESPONSE_DNS_CNAME:
            if(p->dataLenght > 0){
                p->dataLenght--;
            }
            else{
                if (p->currentAnswers != p->totalAnswers){
                    p->currentState = RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE;
                }
                else{
                    p->addresses = realloc(p->addresses, p->totalAnswers*sizeof(struct IpAddress));
                    p->currentState = RESPONSE_DNS_DONE;
                }
            }

        case RESPONSE_DNS_IPV4_ADDRESS:
            
            p->addresses[p->currentAnswers].addr.ipv4.s_addr = (p->addresses[p->currentAnswers].addr.ipv4.s_addr << 8) + b;
        
            p->counter--;

            if(p->counter == 0){
                p->addresses[p->currentAnswers].addr.ipv4.s_addr = htonl(p->addresses[p->currentAnswers].addr.ipv4.s_addr);
                p->currentAnswers++;
                
                if(p->currentAnswers != p->totalAnswers){
                    p->currentState = RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE;
                }
                else{
                    p->addresses = realloc(p->addresses, p->totalAnswers*sizeof(struct IpAddress));
                    p->currentState = RESPONSE_DNS_DONE;
                }
            }
        break;

        case RESPONSE_DNS_IPV6_ADDRESS:
            
            p->addresses[p->currentAnswers].addr.ipv6.s6_addr[p->dataLenght - p->counter] = b;
        
            p->counter--;

            if(p->counter == 0){
                p->currentAnswers++;

                if(p->currentAnswers != p->totalAnswers){
                    p->currentState = RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE;
                }
                else{
                    p->addresses = realloc(p->addresses, p->totalAnswers*sizeof(struct IpAddress));
                    p->currentState = RESPONSE_DNS_DONE;
                }
            }
        break;

        case RESPONSE_DNS_ERROR:
        case RESPONSE_DNS_DONE:
            // Nada que hacer
        break;


        default:
            p->currentState = RESPONSE_DNS_ERROR;
        break;
    }

    return p->currentState;
}

bool response_dns_parser_consume(Buffer *buffer, ResponseDnsParser *p, bool *errored) {

    uint8_t byte;

    while(!response_dns_parser_is_done(p->currentState, errored) && buffer_can_read(buffer)) {
        
        byte = buffer_read(buffer);
        response_dns_parser_feed(p, byte); 
    }

    return response_dns_parser_is_done(p->currentState, errored);
}

bool response_dns_parser_is_done(enum ResponseDnsParserState state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {
        case RESPONSE_DNS_DONE:

            return true;
        break;

        case RESPONSE_DNS_TRANSACTION_STATE:
        case RESPONSE_DNS_FLAGS_STATE:
        case RESPONSE_DNS_QUESTIONS_HIGH:
        case RESPONSE_DNS_QUESTIONS_LOW:
        case RESPONSE_DNS_ANSWERS_HIGH:
        case RESPONSE_DNS_ANSWERS_LOW:
        case RESPONSE_DNS_AUTHORITY:
        case RESPONSE_DNS_ADITIONAL:
        case RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE:
        case RESPONSE_DNS_QUERIES_NAME_REFERENCE_SECOND_BYTE:
        case RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES:
        case RESPONSE_DNS_QUERIES_TYPE:
        case RESPONSE_DNS_QUERIES_CLASS:
        case RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE:
        case RESPONSE_DNS_REFERENCE_SECOND_BYTE:
        case RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES:
        case RESPONSE_DNS_ANSWERS_TYPE_LOW:
        case RESPONSE_DNS_ANSWERS_TYPE_HIGH:
        case RESPONSE_DNS_ANSWERS_CLASS:
        case RESPONSE_DNS_ANSWERS_TTL:
        case RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH:
        case RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW:
        case RESPONSE_DNS_IPV4_ADDRESS:
        case RESPONSE_DNS_IPV6_ADDRESS:
        
            return false;
        break;

        case RESPONSE_DNS_ERROR:
        default:
            if(errored != NULL)
                *errored = true;

            return true;
        break;
    }
}


  
char * response_dns_parser_error_message(enum ResponseDnsParserState state) {
    switch(state) {
        case RESPONSE_DNS_DONE:
        case RESPONSE_DNS_TRANSACTION_STATE:
        case RESPONSE_DNS_FLAGS_STATE:
        case RESPONSE_DNS_QUESTIONS_HIGH:
        case RESPONSE_DNS_QUESTIONS_LOW:
        case RESPONSE_DNS_ANSWERS_HIGH:
        case RESPONSE_DNS_ANSWERS_LOW:
        case RESPONSE_DNS_AUTHORITY:
        case RESPONSE_DNS_ADITIONAL:
        case RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE:
        case RESPONSE_DNS_QUERIES_NAME_REFERENCE_SECOND_BYTE:
        case RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES:
        case RESPONSE_DNS_QUERIES_TYPE:
        case RESPONSE_DNS_QUERIES_CLASS:
        case RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE:
        case RESPONSE_DNS_REFERENCE_SECOND_BYTE:
        case RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES:
        case RESPONSE_DNS_ANSWERS_TYPE_LOW:
        case RESPONSE_DNS_ANSWERS_TYPE_HIGH:
        case RESPONSE_DNS_ANSWERS_CLASS:
        case RESPONSE_DNS_ANSWERS_TTL:
        case RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH:
        case RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW:
        case RESPONSE_DNS_IPV4_ADDRESS:
        case RESPONSE_DNS_IPV6_ADDRESS:
        
            return "Dns response: no error";
        break;

        case RESPONSE_DNS_ERROR:
        default:
            return "Dns response: invalid state";
        break;
    }
}

