#ifndef CLIENT_RECIEVERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_RECIEVERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

void add_user_reciever(int fd);

void remove_user_reciever(int fd);

void toggle_password_spoofing_reciever(int fd);

void toggle_connection_clean_up_reciever(int fd);

void set_buffer_size_reciever(int fd);

void set_selector_timeout_reciever(int fd);

void set_connection_timeout_reciever(int fd);

void list_users_reciever(int fd);

void total_historic_connections_reciever(int fd);

void current_connections_reciever(int fd);

void max_current_conections_reciever(int fd);

void total_bytes_sent_reciever(int fd);

void total_bytes_received_reciever(int fd);

void connected_users_reciever(int fd);

void user_count_reciever(int fd);

void buffer_sizes_reciever(int fd);

void selector_timeout_reciever(int fd);

void connection_timeout_reciever(int fd);

void user_total_concurrent_connections_reciever(int fd);

#endif