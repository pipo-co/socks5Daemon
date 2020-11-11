#ifndef STATISTICS_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define STATISTICS_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdint.h>
#include <stdbool.h>

typedef struct Socks5Statistics {
    
    uint64_t bytesSent;
    uint64_t bytesReceived;
    
    uint64_t totalConnections;
    uint16_t currentConnections;
    uint16_t maxConcurrentConnections;  //Record
    
    uint8_t currentUserCount;
} Socks5Statistics;

extern Socks5Statistics statistics;

void statistics_init(void);

void statistics_inc_current_connection(void);

void statistics_dec_current_connection();

void statistics_add_bytes_sent(uint64_t bytes);

void statistics_add_bytes_received(uint64_t bytes);

void statistics_inc_current_user_count(void);

void statistics_dec_current_user_count(void);

#endif