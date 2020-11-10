#ifndef CLIENT_SENDERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_SENDERS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

#include <stdbool.h>

/* 
 *  @return bool 
 * 	- false -> hubieron errores de conexion.
 * 	- true -> se envio toda la solicitud.  
*/

bool list_users_sender(int fd);

bool total_historic_connections_sender(int fd);

bool current_connections_sender(int fd);

bool max_concurrent_conections_sender(int fd);

bool total_bytes_sent_sender(int fd);

bool total_bytes_received_sender(int fd);

bool connected_users_sender(int fd);

bool total_user_count_sender(int fd);

bool buffer_sizes_sender(int fd);

bool selector_timeout_sender(int fd);

bool connection_timeout_sender(int fd);

bool user_total_current_connections_sender(int fd);

bool add_user_sender(int fd);

bool remove_user_sender(int fd);

bool toggle_password_spoofing_sender(int fd);

bool toggle_connection_clean_up_sender(int fd);

bool set_buffer_size_sender(int fd);

bool set_selector_timeout_sender(int fd);

bool set_connection_timeout_sender(int fd);

#endif