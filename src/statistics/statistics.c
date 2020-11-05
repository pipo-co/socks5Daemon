#include "statistics.h"

#include <string.h>
#include <stdio.h>

Socks5Statistics statistics;


void statistics_init() {
    memset(&statistics, 0, sizeof(statistics));
}

void statistics_inc_current_connection() {
    statistics.currentConnections++;
    statistics.totalConnections++;

    if(statistics.currentConnections > statistics.maxConcurrentConnections) {
        statistics.maxConcurrentConnections = statistics.currentConnections;
    }
}

void statistics_dec_current_connection(bool byInactivity) {
    statistics.currentConnections--;

    if(byInactivity) {
        statistics.connectionsClearedByInactivity++;
    }
}

void statistics_add_bytes_sent(uint64_t bytes) {
    statistics.bytesSent += bytes;
}

void statistics_add_bytes_received(uint64_t bytes) {
    statistics.bytesReceived += bytes;
}

void statistics_inc_current_user_count() {
    statistics.currentUserCount++;
}

void statistics_dec_current_user_count() {
    statistics.currentUserCount--;
}

void statistics_print() {
    fprintf(stderr, "TotalCon:%ld CurrentCon:%d MaxCurrCon:%ld BytesSent:%ld BytesRec:%ld ClosByInac:%ld UsersCon:%d\n",
        statistics.totalConnections, statistics.currentConnections, statistics.maxConcurrentConnections,
                statistics.bytesSent, statistics.bytesReceived, statistics.connectionsClearedByInactivity,
                    statistics.currentUserCount);
}