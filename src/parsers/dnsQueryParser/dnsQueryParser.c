#include "parsers/dnsQueryParser/dnsQueryParser.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct DoHHeader{
    char * addr;
    uint16_t port;
    char * hostname;
    char * path;
    char * query;
    char * httpVersion;
} DoHHeader;

#define BUFSIZE 1024

char *method = "POST ";
char *crlf = "\r\n";
char *acceptMessage = "Accept: application/dns-message";
char *contentType = "Content-type: application/dns-message";
char *contentLength = "Content-length: ";

DoHHeader doh = {
    .addr = "127.0.0.1",
    .port = 53,
    .path = "/dns-query",
    .httpVersion = " HTTP/1.1"
};
size_t build_dns_query(char * domain, uint8_t *buffer, size_t size) ;
uint8_t *convert_domain(char * domain, size_t *nbytes);
// int main() {

//     uint8_t query[BUFSIZE];
//     char message[BUFSIZE];
//     size_t size = 0;
//     // size_t querySize = build_dns_query("google.com", query, BUFSIZE);
//     size_t querySize = build_dns_query("www.example.com", query, BUFSIZE);

//     memcpy(message + size, method, strlen(method));
//     size += strlen(method);
//     memcpy(message + size, doh.path, strlen(doh.path));
//     size += strlen(doh.path);
//     memcpy(message + size, doh.httpVersion, strlen(doh.httpVersion));
//     size += strlen(doh.httpVersion);
//     memcpy(message + size, crlf, strlen(crlf));
//     size += strlen(crlf);

//     memcpy(message + size, acceptMessage, strlen(acceptMessage));
//     size += strlen(acceptMessage);
//     memcpy(message + size, crlf, strlen(crlf));
//     size += strlen(crlf);

//     memcpy(message + size, contentType, strlen(contentType));
//     size += strlen(contentType);
//     memcpy(message + size, crlf, strlen(crlf));
//     size += strlen(crlf);

//     memcpy(message + size, contentLength, strlen(contentLength));
//     size += strlen(contentLength);
//     size += sprintf(message + size, "%zu", querySize);
//      //Length del mensaje
//     memcpy(message + size, crlf, strlen(crlf));
//     size += strlen(crlf);
//     memcpy(message + size, crlf, strlen(crlf));
//     size += strlen(crlf);

//     memcpy(message + size, query, querySize);
//     size += querySize;

    
//     int fd = socket(AF_INET, SOCK_STREAM, 0);
//     struct sockaddr_in a;
//     memset(&a, 0, sizeof(a));
//     a.sin_family = AF_INET;
//     a.sin_port = htons(8080);
//     inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
//     // inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);
//     connect(fd, (struct sockaddr *)&a, sizeof(a));
//     send(fd, message, size, 0);

//     // sendto(fd, query, querySize, 0, (struct sockaddr*)&a, sizeof(a));



//     return 0;
// }

#define QR_QUERY 0
#define OPCODE_QUERY 0
#define NO_AUTHORITY 0
#define NOT_TRUNCATE 0
#define RECURSIVE_QUERY 1
#define QUESTIONS_COUNT 1
#define AAAA 28
#define A 1
#define IN 1

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

struct dns_packet {
	struct dns_header header;
//	struct dns_question question;
	char *data;
	u_int16_t data_size;
};

struct dns_response_packet {
	char *name;
	u_int16_t type;
	u_int16_t class;
	u_int32_t ttl;
	u_int16_t rdlength;
	char *rdata;
};

struct dns_question {
	uint8_t *qname;
	u_int16_t qtype;
	u_int16_t qclass;
};

uint8_t *convert_domain(char * domain, size_t *nbytes) {
    uint8_t *ans = malloc(255);
    uint8_t size = 0;
    size_t length = strlen(domain);
    
    if(*domain == '.') {
        goto finally;
    }

    char *next;
    printf("%s\n",domain);
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
        printf("%ld\n",next - domain);
        printf("%s\n",next);
        printf("%s\n",domain);
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

size_t build_dns_query(char * domain, uint8_t *buffer, size_t size) {
    
    uint8_t *initBuffer = buffer;

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
        .qdcount = htons(QUESTIONS_COUNT),
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    struct dns_question ipv4Question = {
	    .qtype = htons(A),
	    .qclass = htons(IN),
    };

    // struct dns_question ipv6Question = {
	//     .qtype = htons(AAAA),
	//     .qclass = htons(IN),
    // };
    size_t domainLength;
    ipv4Question.qname = convert_domain(domain, &domainLength);
    // ipv6Question.qname = convert_domain(domain, &domainLength);
    

    if(size < sizeof(header) + sizeof(ipv4Question) /*+ sizeof(ipv6Question)*/)
        return 0;

    memcpy(buffer, &header, sizeof(header));
    buffer += sizeof(header);

    printf("%s",ipv4Question.qname);
    memcpy(buffer, ipv4Question.qname, domainLength);
    buffer += domainLength;
    memcpy(buffer, &ipv4Question.qtype, sizeof(ipv4Question.qtype));
    buffer += sizeof(ipv4Question.qtype);
    memcpy(buffer, &ipv4Question.qclass, sizeof(ipv4Question.qclass));
    buffer += sizeof(ipv4Question.qclass);

    // memcpy(buffer, ipv6Question.qname, domainLength);
    // buffer += domainLength;
    // memcpy(buffer, &ipv6Question.qtype, sizeof(ipv6Question.qtype));
    // buffer += sizeof(ipv6Question.qtype);
    // memcpy(buffer, &ipv6Question.qclass, sizeof(ipv6Question.qclass));
    // buffer += sizeof(ipv6Question.qclass);

    

    return buffer - initBuffer;
}