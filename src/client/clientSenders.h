#ifndef CLIENT_SENDERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_SENDERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

void list_users_sender(int fd);

void total_historic_connections_sender(int fd);

void current_connections_sender(int fd);

void max_current_conections_sender(int fd);

void total_bytes_sent_sender(int fd);

void total_bytes_received_sender(int fd);

void connected_users_sender(int fd);

void user_count_sender(int fd);

void buffer_sizes_sender(int fd);

void selector_timeout_sender(int fd);

void connection_timeout_sender(int fd);

void user_total_concurrent_connections_sender(int fd);

void add_user_sender(int fd);

void remove_user_sender(int fd);

void toggle_password_spoofing_sender(int fd);

void toggle_connection_clean_up_sender(int fd);

void set_buffer_size_sender(int fd);

void set_selector_timeout_sender(int fd);

void set_connection_timeout_sender(int fd);

#endif