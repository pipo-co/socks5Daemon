#ifndef DNS_DEFS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define DNS_DEFS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

typedef enum DnsAddressTypes { 
    DNS_IP4_ADD_TYPE            = 0x01, 
    DNS_IP6_ADD_TYPE            = 0x04,
} DnsAddressTypes;

typedef enum DnsAddressLengths { 
    DNS_IP4_ADD_LENGTH           = 4, 
    DNS_IP6_ADD_LENGTH           = 16,
} DnsAddressLengths;

typedef enum DnsQueryTypes {
    DNS_QUERY_A                  = 0x01,
    DNS_QUERY_AAAA               = 0x1c,
} DnsQueryTypes;

#endif
