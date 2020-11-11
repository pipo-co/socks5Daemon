#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "utilities/base64/base64.h"
#include "parsers/dns/dohBuilder.h"
#include "dnsDefs.h"

#define MAX(x, y) (x >= y ? x : y)

static char crlf[] = "\r\n";
static char acceptMessage[] = "Accept: application/dns-message";
static char contentType[] = "Content-type: application/dns-message";
static char contentLength[] = "Content-length: ";
static char hostName[] = "Host: ";

enum DnsQueryParserBufferSizes {
    MAX_QUERY_SIZE = 10,
    MAX_FQDN_SIZE = 255, // Header / First count / FQDN length / '\0' / qtype / qlength
    MAX_DNS_QUERY_SIZE = 273, // Header / First count / FQDN length / '\0' / qtype / qlength
    MAX_DOH_QUERY_SIZE = 4096, 
    MAX_PATH_SIZE = 2048,
};

enum DnsQueryParserQueryFlags {
    QR_QUERY = 0,
    OPCODE_QUERY = 0,
    NO_AUTHORITY = 0,
    NOT_TRUNCATE = 0,
    RECURSIVE_QUERY = 1,
    QUESTIONS_COUNT = 1,
    IN = 1,
};

struct dns_header {
	u_int16_t id; /* a 16 bit identifier assigned by the client */
	u_int16_t qr:1;
	u_int16_t opcode:4;
	u_int16_t aa:1;
	u_int16_t tc:1;
	u_int16_t rd:1;
	u_int16_t ra:1;
	u_int16_t z:3;
	u_int16_t rcode:4;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
};

struct dns_question {
	uint8_t *qname;
	u_int16_t qtype;
	u_int16_t qclass;
};

struct dns_header header = {
        .id = 0,
        .qr = RECURSIVE_QUERY,
        .opcode = OPCODE_QUERY,
        .aa = NO_AUTHORITY,
        .tc = NOT_TRUNCATE,
        .rd = QR_QUERY,
        .ra = 0,
        .z = 0,
        .rcode = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
};

static uint8_t *doh_builder_convert_domain(char * domain, uint8_t * buff);
static size_t doh_builder_build_dns_query(char * domain, uint16_t qtype, uint8_t *buffer, size_t size) ;
static void doh_builder_add_header_value(uint8_t *buff, size_t *size, char *header, char *value);
static void doh_builder_add_request_line(uint8_t *buff, size_t *size, char *method, char *path, char *version);

int doh_builder_build(Buffer * buff, char * domain, uint16_t qtype, Socks5Args * args, size_t bufSize) {

    // Socks5Args * args = socks5_get_args();
    struct doh *doh = &args->doh;
    char *method = doh->method == GET ? "GET" : "POST";

    if(qtype == AF_INET){
        qtype = DNS_QUERY_A;
    } else if(qtype == AF_INET6) {
        qtype = DNS_QUERY_AAAA;
    } else {
        return -1;
    }

    size_t size = 0;
    uint8_t dohQuery[MAX_DOH_QUERY_SIZE];
    
    uint8_t dnsQuery[MAX_DNS_QUERY_SIZE];
    size_t querySize = doh_builder_build_dns_query(domain, qtype, dnsQuery, MAX_DNS_QUERY_SIZE);
    if(querySize == 0) {
        return -1;
    }
        
    char path[MAX_PATH_SIZE];

    strcpy(path, doh->path);
    
    if(doh->method == GET) {
        char b64Query[BASE64_ENCODE_SIZE(MAX_DNS_QUERY_SIZE)];
        base64_encode(dnsQuery, querySize, b64Query, false);
        strcat(path, doh->query);
        strcat(path, b64Query);
    }

    doh_builder_add_request_line(dohQuery, &size, method, path, doh->httpVersion);
    doh_builder_add_header_value(dohQuery,&size, acceptMessage, NULL);

    doh_builder_add_header_value(dohQuery,&size, hostName, doh->host);

    if(doh->method == POST) {
        doh_builder_add_header_value(dohQuery, &size, contentType, NULL);

        char querySizeBuff[MAX_QUERY_SIZE];
        sprintf(querySizeBuff + size, "%zu", querySize);

        doh_builder_add_header_value(dohQuery, &size, contentLength, querySizeBuff);
    }

    //End of headers
    memcpy(dohQuery + size, crlf, strlen(crlf));
    size += strlen(crlf);

    if(doh->method == POST) {
        memcpy(dohQuery + size, dnsQuery, querySize);
        size += querySize;
    }

    uint8_t *ans = malloc(MAX(size, bufSize));
    if(ans == NULL) {
        return -1;
    }


    memcpy(ans, dohQuery, size);
    buffer_init(buff, size, ans);
    buffer_write_adv(buff, size);

    return 0;
}

static size_t doh_builder_build_dns_query(char * domain, uint16_t qtype, uint8_t *buffer, size_t size) {
    
    uint8_t *initBuffer = buffer;

    if(size < MAX_DNS_QUERY_SIZE || strlen(domain) > MAX_FQDN_SIZE)
        return 0;

    header.qdcount = htons(QUESTIONS_COUNT);

    struct dns_question question;

    question.qtype = htons(qtype);
    question.qclass = htons(IN);

    memcpy(buffer, &header, sizeof(header));
    buffer += sizeof(header);

    buffer = doh_builder_convert_domain(domain, buffer);

    memcpy(buffer, &question.qtype, sizeof(question.qtype));
    buffer += sizeof(question.qtype);
    memcpy(buffer, &question.qclass, sizeof(question.qclass));
    buffer += sizeof(question.qclass);


    return buffer - initBuffer;
}

// Asume que buff tiene espacio suficiente
static uint8_t *doh_builder_convert_domain(char * domain, uint8_t * buff) {
    
    char *next;

    if(*domain == '.') {
        goto finally;
    }

    while(*domain){
        next = strchr(domain, '.');
        if(next == NULL){
            *(buff++) = strlen(domain);
            while(*domain){
                *(buff++) = *(domain++);
            }
            goto finally;
        }
        *(buff++) = next - domain;
        while(next != domain){
            *(buff++) = *(domain++);
        }
        domain++;
    }

finally:
    *(buff++) = '\0';
    return buff;
}

static void doh_builder_add_header_value(uint8_t *buff, size_t *size, char *header, char *value) {
    
    memcpy(buff + *size, header, strlen(header));
    *size += strlen(header);

    if(value != NULL) {
        memcpy(buff + *size, value, strlen(value));
        *size += strlen(value);
    }

    memcpy(buff + *size, crlf, strlen(crlf));
    *size += strlen(crlf);
}

static void doh_builder_add_request_line(uint8_t *buff, size_t *size, char *method, char *path, char *version) {
    
    memcpy(buff + *size, method, strlen(method));
    *size += strlen(method);

    buff[(*size)++] = ' ';

    memcpy(buff + *size, path, strlen(path));
    *size += strlen(path);
    
    buff[(*size)++] = ' ';

    memcpy(buff + *size, version, strlen(version));
    *size += strlen(version);
    memcpy(buff + *size, crlf, strlen(crlf));
    *size += strlen(crlf);
}
