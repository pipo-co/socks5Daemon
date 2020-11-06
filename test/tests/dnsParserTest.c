#include <stdlib.h>
#include <check.h>
#include <arpa/inet.h>

// Archivo testeado
#include "parsers/dns/dnsParser.c"

uint8_t request_dns_parser_test_input_success[] = {
    0x55, 0x09, 0x81, 0x20, 0x00, 0x01, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 
    0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x01, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f, 
    0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x04, 0xac, 0xd9, 0xac, 0x2e,
};

uint8_t request_dns_parser_test_input_multiple_success[] = {
    0x16, 0x1f, 0x81, 0x20, 0x00, 0x01, 0x00, 0x03, 
    0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 
    0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x01, 0x00, 0x01, 0x06, 0x61, 0x6d, 0x61, 
    0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x04, 0xb0, 0x20, 0x62, 0xa6, 0xc0, 0x1c, 
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x04, 0xcd, 0xfb, 0xf2, 0x67, 0xc0, 0x1c, 
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x04, 0xb0, 0x20, 0x67, 0xcd 
};

uint8_t request_dns_parser_test_input_success_ipv6[] = {
    0x2b, 0x26, 0x81, 0x20, 0x00, 0x01, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 
    0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x1c, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f, 
    0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x10, 0x28, 0x00, 0x03, 0xf0, 0x40, 0x02, 
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x20, 0x0e
};



START_TEST (response_dns_test_parser_init) {

    ResponseDnsParser * p = malloc(sizeof(*p));
    response_dns_parser_init(p);

    ck_assert_uint_eq(p->currentState, RESPONSE_DNS_TRANSACTION_STATE);
    //ck_assert_uint_eq(p->addresses, NULL);
    ck_assert_uint_eq(p->totalQuestions, 0);
    ck_assert_uint_eq(p->totalAnswers, 0);
    ck_assert_uint_eq(p->currentAnswers, 0);
    ck_assert_uint_eq(p->bytesWritten, 0);
    ck_assert_uint_eq(p->currentType, 0);
    ck_assert_uint_eq(p->counter, 0);

    free(p);
}
END_TEST

START_TEST (response_dns_test_parser_feed_success) {

    ResponseDnsParser * p = malloc(sizeof(*p));

    size_t pos = 0;
    size_t i = 0;
    
    response_dns_parser_init(p);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_TRANSACTION_STATE);
    
    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_FLAGS_STATE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_FLAGS_STATE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUESTIONS_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUESTIONS_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_HIGH);
    ck_assert_uint_eq(p->totalQuestions, 1);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_AUTHORITY);
    ck_assert_uint_eq(p->totalAnswers, 1);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_AUTHORITY);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ADITIONAL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ADITIONAL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 6);

    while (pos < 18)
    {   
        ck_assert_uint_eq(p->bytesWritten, 6 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 3);
    i=0;

    while (pos < 22)
    {   
        ck_assert_uint_eq(p->bytesWritten, 3 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_TYPE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_TYPE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 6);
    i = 0;

    while (pos < 34)
    {   
        ck_assert_uint_eq(p->bytesWritten, 6 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 3);
    i=0;

    while (pos < 38)
    {   
        ck_assert_uint_eq(p->bytesWritten, 3 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    ck_assert_uint_eq(p->dataLenght, 4);
    ck_assert_uint_eq(p->addresses[p->currentAnswers].ipType, IPV4);
    ck_assert_uint_eq(p->counter, 4);

    while (p->counter > 1)
    {   
        response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_DONE);
    ck_assert_uint_eq(p->currentAnswers, 1);
    char buffer[50];
    inet_ntop(AF_INET, &p->addresses[p->currentAnswers-1].addr.ipv4, buffer,50);
    ck_assert(!strcmp(buffer, "172.217.172.46"));

    free(p->addresses);
    free(p);

}
END_TEST

START_TEST (response_dns_test_parser_consume) {

    ResponseDnsParser * p = malloc(sizeof(*p));
    response_dns_parser_init(p);

    bool errored;

    Buffer *b = malloc(sizeof(*b));

    buffer_init(b, N(request_dns_parser_test_input_success), request_dns_parser_test_input_success);
    buffer_write_adv(b, N(request_dns_parser_test_input_success));


    ck_assert(response_dns_parser_consume(b, p, &errored));

    ck_assert(!errored);

    ck_assert_uint_eq(p->currentAnswers, 1);

    ck_assert(response_dns_parser_is_done(p->currentState, &errored));

    ck_assert(!errored);

    free(b);
    free(p->addresses);
    free(p);
}
END_TEST

START_TEST (response_dns_test_parser_feed_multiple_success) {

    ResponseDnsParser * p = malloc(sizeof(*p));

    size_t pos = 0;
    size_t i = 0;
    
    response_dns_parser_init(p);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_TRANSACTION_STATE);
    
    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_FLAGS_STATE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_FLAGS_STATE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUESTIONS_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUESTIONS_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_HIGH);
    ck_assert_uint_eq(p->totalQuestions, 1);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_AUTHORITY);
    ck_assert_uint_eq(p->totalAnswers, 3);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_AUTHORITY);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ADITIONAL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ADITIONAL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 6);

    while (pos < 18)
    {   
        ck_assert_uint_eq(p->bytesWritten, 6 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 3);
    i=0;

    while (pos < 22)
    {   
        ck_assert_uint_eq(p->bytesWritten, 3 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_TYPE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_TYPE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 6);
    i = 0;

    while (pos < 34)
    {   
        ck_assert_uint_eq(p->bytesWritten, 6 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 3);
    i=0;

    while (pos < 38)
    {   
        ck_assert_uint_eq(p->bytesWritten, 3 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    ck_assert_uint_eq(p->dataLenght, 4);
    ck_assert_uint_eq(p->addresses[p->currentAnswers].ipType, IPV4);
    ck_assert_uint_eq(p->counter, 4);

    while (p->counter > 1)
    {   
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);
    ck_assert_uint_eq(p->currentAnswers, 1);
    char buffer[50];
    inet_ntop(AF_INET, &p->addresses[p->currentAnswers-1].addr.ipv4, buffer,50);
    ck_assert(!strcmp(buffer, "176.32.98.166"));

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_REFERENCE_SECOND_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    ck_assert_uint_eq(p->dataLenght, 4);
    ck_assert_uint_eq(p->addresses[p->currentAnswers].ipType, IPV4);
    ck_assert_uint_eq(p->counter, 4);

    while (p->counter > 1)
    {   
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);
    ck_assert_uint_eq(p->currentAnswers, 2);

    inet_ntop(AF_INET, &p->addresses[p->currentAnswers-1].addr.ipv4, buffer,50);
    ck_assert(!strcmp(buffer, "205.251.242.103"));

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_REFERENCE_SECOND_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    ck_assert_uint_eq(p->dataLenght, 4);
    ck_assert_uint_eq(p->addresses[p->currentAnswers].ipType, IPV4);
    ck_assert_uint_eq(p->counter, 4);

    while (p->counter > 1)
    {   
        response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_IPV4_ADDRESS);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_multiple_success[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_DONE);
    ck_assert_uint_eq(p->currentAnswers, 3);
    
    inet_ntop(AF_INET, &p->addresses[p->currentAnswers-1].addr.ipv4, buffer,50);
    ck_assert(!strcmp(buffer, "176.32.103.205"));

    free(p->addresses);
    free(p);

}
END_TEST

START_TEST (response_dns_test_parser_consume_multiple_success) {

    ResponseDnsParser * p = malloc(sizeof(*p));
    response_dns_parser_init(p);

    bool errored;

    Buffer *b = malloc(sizeof(*b));

    buffer_init(b, N(request_dns_parser_test_input_multiple_success), request_dns_parser_test_input_multiple_success);
    buffer_write_adv(b, N(request_dns_parser_test_input_multiple_success));


    ck_assert(response_dns_parser_consume(b, p, &errored));

    ck_assert(!errored);

    ck_assert_uint_eq(p->currentAnswers, 3);

    ck_assert(response_dns_parser_is_done(p->currentState, &errored));

    ck_assert(!errored);

    free(b);
    free(p->addresses);
    free(p);
}
END_TEST

START_TEST (response_dns_test_parser_feed_success_ipv6) {

    ResponseDnsParser * p = malloc(sizeof(*p));

    size_t pos = 0;
    size_t i = 0;
    
    response_dns_parser_init(p);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_TRANSACTION_STATE);
    
    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_FLAGS_STATE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_FLAGS_STATE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUESTIONS_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUESTIONS_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_HIGH);
    ck_assert_uint_eq(p->totalQuestions, 1);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_AUTHORITY);
    ck_assert_uint_eq(p->totalAnswers, 1);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_AUTHORITY);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ADITIONAL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ADITIONAL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 6);

    while (pos < 18)
    {   
        ck_assert_uint_eq(p->bytesWritten, 6 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 3);
    i=0;

    while (pos < 22)
    {   
        ck_assert_uint_eq(p->bytesWritten, 3 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_TYPE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_TYPE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_QUERIES_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 6);
    i = 0;

    while (pos < 34)
    {   
        ck_assert_uint_eq(p->bytesWritten, 6 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    ck_assert_uint_eq(p->bytesWritten, 3);
    i=0;

    while (pos < 38)
    {   
        ck_assert_uint_eq(p->bytesWritten, 3 - i++);
        response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_OTHER_BYTES);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_NAME_FIRST_BYTE);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TYPE_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_CLASS);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_TTL);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_HIGH);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_ANSWERS_DATA_LENGTH_LOW);

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_IPV6_ADDRESS);
    ck_assert_uint_eq(p->dataLenght, 16);
    ck_assert_uint_eq(p->addresses[p->currentAnswers].ipType, IPV6);
    ck_assert_uint_eq(p->counter, 16);

    while (p->counter > 1)
    {   
        response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
        ck_assert(p->currentState == RESPONSE_DNS_IPV6_ADDRESS);
    }

    response_dns_parser_feed(p, request_dns_parser_test_input_success_ipv6[pos++]);
    ck_assert(p->currentState == RESPONSE_DNS_DONE);
    ck_assert_uint_eq(p->currentAnswers, 1);
    char buffer[100];

    inet_ntop(AF_INET6, &p->addresses[p->currentAnswers-1].addr.ipv6, buffer, 100);

    ck_assert(!strcmp(buffer,"2800:3f0:4002:800::200e"));
    
    free(p->addresses);
    free(p);

}
END_TEST

Suite * response_dns_parser_test_suite(void) {

    Suite *s   = suite_create("responseDnsParser");
    TCase *tc  = tcase_create("core");

    tcase_add_test(tc, response_dns_test_parser_init);
    tcase_add_test(tc, response_dns_test_parser_feed_success);
    tcase_add_test(tc, response_dns_test_parser_consume);
    tcase_add_test(tc, response_dns_test_parser_feed_multiple_success);
    tcase_add_test(tc, response_dns_test_parser_consume_multiple_success);
    tcase_add_test(tc, response_dns_test_parser_feed_success_ipv6);


    suite_add_tcase(s, tc);
    return s;
}