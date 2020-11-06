#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utilities/base64/base64.h"
#include "parsers/dns/dohBuilder.h"
#include "socks5/socks5.h"

static char crlf[] = "\r\n";
static char acceptMessage[] = "Accept: application/dns-message";
static char contentType[] = "Content-type: application/dns-message";
static char contentLength[] = "Content-length: ";
static char hostName[] = "Host: ";

enum DnsQueryParserBufferSizes {
    MAX_DOH_QUERY_SIZE = 2048, 
    MAX_DNS_QUERY_SIZE = 300,
    MAX_DOMAIN_NAME = 256,
    MAX_PATH_SIZE = 1024,
    MAX_QUERY_SIZE = 10,
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

static size_t build_dns_query(char * domain, uint16_t qtype, uint8_t *buffer, size_t size) ;
static uint8_t *convert_domain(char * domain, size_t *nbytes);
static void add_header_value(uint8_t *buff, size_t *size, char *header, char *value);
static void add_request_line(uint8_t *buff, size_t *size, char *method, char *path, char *version);

void doh_builder_build(Buffer * buff, char * domain, uint16_t qtype) {

    Socks5Args * args = socks5_get_args();
    struct doh *doh = &args->doh;
    char *method = doh->method == GET ? "GET" : "POST";

    if(qtype == AF_INET){
        qtype = A;
    } else if(qtype == AF_INET6) {
        qtype = AAAA;
    } else {
        //Error
    }


    size_t size = 0;
    uint8_t *dohQuery = malloc(MAX_DOH_QUERY_SIZE);
    
    uint8_t dnsQuery[MAX_DNS_QUERY_SIZE];
    size_t querySize = build_dns_query(domain, qtype, dnsQuery, MAX_DNS_QUERY_SIZE);
    
    char path[MAX_PATH_SIZE];
    memset(path, '\0', MAX_PATH_SIZE);
    strcpy(path, doh->path);
    
    if(doh->method == GET) {
        size_t b64Lenght;
        char * b64Query = base64_encode(dnsQuery, querySize, &b64Lenght);
        strcat(path, doh->query);
        strncat(path, b64Query, b64Lenght);
        size_t pathLen = strlen(path);
        for (size_t i = 0; path[pathLen - i - 1] == '=' ; i++) {
            path[pathLen - i - 1] = '\0';
        }
        
    }

    add_request_line(dohQuery, &size, method, path, doh->httpVersion);

    add_header_value(dohQuery,&size, acceptMessage, NULL);

    add_header_value(dohQuery,&size, hostName, doh->host);

    if(doh->method == POST) {
        add_header_value(dohQuery,&size, contentType, NULL);

        char querySizeBuff[MAX_QUERY_SIZE];
        sprintf(querySizeBuff + size, "%zu", querySize);

        add_header_value(dohQuery, &size, contentLength, querySizeBuff);
    }

    //End of headers
    memcpy(dohQuery + size, crlf, strlen(crlf));
    size += strlen(crlf);

    if(doh->method == POST) {
        memcpy(dohQuery + size, dnsQuery, querySize);
        size += querySize;
    }
    
    buffer_init(buff, MAX_DOH_QUERY_SIZE, dohQuery);
    buffer_write_adv(buff, size);

    return;
}

static size_t build_dns_query(char * domain, uint16_t qtype, uint8_t *buffer, size_t size) {
    
    uint8_t *initBuffer = buffer;

    size_t domainLength;

    header.qdcount = htons(QUESTIONS_COUNT);

    struct dns_question question;

    question.qname = convert_domain(domain, &domainLength);
    question.qtype = htons(qtype);
    question.qclass = htons(IN);
    

    if(size < sizeof(header) + sizeof(question))
        return 0;

    memcpy(buffer, &header, sizeof(header));
    buffer += sizeof(header);

    memcpy(buffer, question.qname, domainLength);
    buffer += domainLength;
    memcpy(buffer, &question.qtype, sizeof(question.qtype));
    buffer += sizeof(question.qtype);
    memcpy(buffer, &question.qclass, sizeof(question.qclass));
    buffer += sizeof(question.qclass);

    free(question.qname);

    return buffer - initBuffer;
}

static uint8_t *convert_domain(char * domain, size_t *nbytes) {
    uint8_t *ans = malloc(MAX_DOMAIN_NAME);
    uint8_t size = 0;
    
    if(*domain == '.') {
        goto finally;
    }

    char *next;
    while(*domain){
        next = strchr(domain, '.');
        if(next == NULL){
            ans[size++] = strlen(domain);
            while(*domain){
                ans[size++] = *domain;
                domain++;
            }
            goto finally;
        }
        ans[size++] = next - domain;
        while(next != domain){
            ans[size++] = *domain;
            domain++;
        }
        domain++;
    }

finally:
    ans[size++] = '\0';
    *nbytes = size;
    return ans;
}

static void add_header_value(uint8_t *buff, size_t *size, char *header, char *value) {
    
    memcpy(buff + *size, header, strlen(header));
    *size += strlen(header);

    if(value != NULL) {
        memcpy(buff + *size, value, strlen(value));
        *size += strlen(value);
    }

    memcpy(buff + *size, crlf, strlen(crlf));
    *size += strlen(crlf);
}

static void add_request_line(uint8_t *buff, size_t *size, char *method, char *path, char *version) {
    
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
