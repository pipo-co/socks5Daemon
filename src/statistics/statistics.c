#include "statistics.h"

#include <string.h>
#include <stdio.h>

Socks5Statistics statistics;


void statistics_init() {
    memset(&statistics, 0, sizeof(statistics));
}

void statistics_inc_current_connection() {

    if(statistics.totalConnections < UINT64_MAX){
        statistics.totalConnections++;
    }

    if(statistics.currentConnections < UINT16_MAX){

        statistics.currentConnections++;

        if(statistics.currentConnections > statistics.maxConcurrentConnections) {
            statistics.maxConcurrentConnections = statistics.currentConnections;
        }
    }
}

void statistics_dec_current_connection() {

    if(statistics.currentConnections > 0){
        statistics.currentConnections--;
    }
}

void statistics_add_bytes_sent(uint64_t bytes) {

    if(statistics.bytesSent + bytes < UINT64_MAX){
        statistics.bytesSent += bytes;
    }
}

void statistics_add_bytes_received(uint64_t bytes) {

    if(statistics.bytesReceived + bytes < UINT64_MAX){
        statistics.bytesReceived += bytes;
    }
}

void statistics_inc_current_user_count() {

    if(statistics.currentUserCount < UINT8_MAX){
        statistics.currentUserCount++;
    }
}

void statistics_dec_current_user_count() {

    if(statistics.currentUserCount > 0){
        statistics.currentUserCount--;
    }
}