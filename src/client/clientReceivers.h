#ifndef CLIENT_RECIEVERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_RECIEVERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

#include <arpa/inet.h>
#include <netinet/in.h> 
#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <stdint.h> 
#include <string.h> 
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

// server {
//      listen  8053;
//      server_name doh;

//      location / {
//         resolver 1.1.1.1 ipv6=off valid=30s;
//         set $empty "";
//         proxy_pass https://doh.opendns.com$empty;
//      }
//  }

void add_user_receiver(int fd);

void remove_user_receiver(int fd);

void toggle_password_spoofing_receiver(int fd);

void toggle_connection_clean_up_receiver(int fd);

void set_buffer_size_receiver(int fd);

void set_selector_timeout_receiver(int fd);

void set_connection_timeout_receiver(int fd);

void list_users_receiver(int fd);

void total_historic_connections_receiver(int fd);

void current_connections_receiver(int fd);

void max_concurrent_conections_receiver(int fd);

void total_bytes_sent_receiver(int fd);

void total_bytes_received_receiver(int fd);

void connected_users_receiver(int fd);

void user_count_receiver(int fd);

void buffer_sizes_receiver(int fd);

void selector_timeout_receiver(int fd);

void connection_timeout_receiver(int fd);

void user_total_concurrent_connections_receiver(int fd);

#endif