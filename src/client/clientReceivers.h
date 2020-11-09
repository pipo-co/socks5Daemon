#ifndef CLIENT_RECIEVERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_RECIEVERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

#include <stdbool.h>

bool add_user_receiver(int fd);

bool remove_user_receiver(int fd);

bool toggle_password_spoofing_receiver(int fd);

bool toggle_connection_clean_up_receiver(int fd);

bool set_buffer_size_receiver(int fd);

bool set_selector_timeout_receiver(int fd);

bool set_connection_timeout_receiver(int fd);

bool list_users_receiver(int fd);

bool total_historic_connections_receiver(int fd);

bool current_connections_receiver(int fd);

bool max_concurrent_conections_receiver(int fd);

bool total_bytes_sent_receiver(int fd);

bool total_bytes_received_receiver(int fd);

bool connected_users_receiver(int fd);

bool user_count_receiver(int fd);

bool buffer_sizes_receiver(int fd);

bool selector_timeout_receiver(int fd);

bool connection_timeout_receiver(int fd);

bool user_total_concurrent_connections_receiver(int fd);

#endif