
#include "client/clientReceivers.h"

static int receiver_uint8(int fd);
static int receiver_uint32(int fd);
static int receiver_uint64(int fd);
static int receiver_user_list(int fd);

void add_user_reciever(int fd){
	status_reciever(MODIFICATION, ADD_USER);
}

void remove_user_reciever(int fd){

}

void toggle_password_spoofing_reciever(int fd){

}

void toggle_connection_clean_up_reciever(int fd){

}

void set_buffer_size_reciever(int fd){

}

void set_selector_timeout_reciever(int fd){

}

void set_connection_timeout_reciever(int fd){

}

void list_users_reciever(int fd){
	user_list_reciever(QUERY, LIST_USER);
}

void total_historic_connections_reciever(int fd){

}

void current_connections_reciever(int fd){

}

void max_current_conections_reciever(int fd){

}

void total_bytes_sent_reciever(int fd){

}

void total_bytes_received_reciever(int fd){

}

void connected_users_reciever(int fd){

}

void user_count_reciever(int fd){

}

void buffer_sizes_reciever(int fd){

}

void selector_timeout_reciever(int fd){

}

void connection_timeout_reciever(int fd){

}

void user_total_concurrent_connections_reciever(int fd){

}

static int receiver_uint8(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	char buffer[UINT8_LENGTH];
	char type, command, response;
      
    do {
		bytes = recv(fd, buffer, UINT8_LENGTH - bytesWritten, MSG_NOSIGNAL);
		
		if(bytes == 0){
			return -1;
		}
		if(bytes > 0){
			bytesReceived += bytes;
		}
		
		if (bytesWritten < bytesReceived){
			if( bytesWritten == 0){
				type = buffer[bytesWritten++];
				printf("TYPE: %c ", type);
			}
			else if (bytesWritten == 1){
				command = buffer[bytesWritten++];
				printf("CMD: %c ", command);
			}
			else {
				response = buffer[bytesWritten++];
				printf("RESPONSE: %c\n", command);
			}
		}
    } while(bytesReceived < UINT8_LENGTH);
    
    return 0;
}

static int receiver_uint32(int fd) {

	char buffer[UINT32_LENGTH];

	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	
	char type, command;
	uint32_t response;
      
    do {
		bytes = recv(fd, buffer, UINT32_LENGTH, MSG_NOSIGNAL);
		if(bytes < 0){
			return -1;
		}
		bytesReceived += bytes;
		if (bytesWritten < bytesReceived){
			if(bytesWritten == 0){
				type = buffer[bytesWritten++];
				printf("TYPE: %c ", type);
			}
			else if (bytesWritten == 1){
				command = buffer[bytesWritten++];
				printf("CMD: %c ", command);
			}
			else {
				response = (buffer[bytesWritten++] >> ((UINT32_LENGTH - bytesWritten)* 8)) & MASK;
				if(bytesReceived == UINT32_LENGTH){
					printf("RESPONSE: %u\n", response);
				}
			}
		}
    } while(bytesReceived < UINT32_LENGTH);
	
	
    
    return 0;
}

static int receiver_uint64(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	char buffer[UINT64_LENGTH];
	char type, command;
	uint32_t response;
      
    do {
		bytes = recv(fd, buffer, UINT64_LENGTH, MSG_NOSIGNAL);
		if(bytes < 0){
			return -1;
		}
		bytesReceived += bytes;
		if (bytesWritten < bytesReceived){
			if(bytesWritten == 0){
				type = buffer[bytesWritten++];
				printf("TYPE: %c ", type);
			}
			else if (bytesWritten == 1){
				command = buffer[bytesWritten++];
				printf("CMD: %c ", command);
			}
			else {
				response = (buffer[bytesWritten++] >> ((UINT64_LENGTH - bytesWritten)* 8)) & MASK;
				if(bytesReceived == UINT64_LENGTH){
						printf("RESPONSE: %lu\n", response);
					}
			}
		}
    } while(bytesReceived < UINT64_LENGTH);
    
    return 0;
}

static int receiver_user_list(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	char intialBuffer[NO_ARGS_LENGTH];
	char type, command;
	uint16_t ucount;
	uint32_t response;
      
    do {
		bytes = recv(fd, intialBuffer, NO_ARGS_LENGTH, MSG_NOSIGNAL);
		if(bytes < 0){
			return -1;
		}
		bytesReceived += bytes;
		if (bytesWritten < bytesReceived){
			if(bytesWritten == 0){
				type = intialBuffer[bytesWritten++];
				printf("TYPE: %c ", type);
			}
			else{
				command = intialBuffer[bytesWritten++];
				printf("CMD: %c ", command);
			}
		}
    } while(bytesReceived < NO_ARGS_LENGTH);

	bytesReceived = 0;

	do {
		bytes= recv(fd, ucount, 1, MSG_NOSIGNAL);
		if(bytes < 0){
			return -1;
		}
		bytesReceived += bytes;
	} while (bytesReceived < 1);

	if(ucount < 0){
		return -1;
	}

	bytesWritten = bytesReceived = 0;
	char userBuffer[MAX_USERNAME + 1] = {0}; //el maximo nombre de usuario mas el ulen
	char username[MAX_USERNAME + 1];
	char ulen;

	while(ucount > 0){
		bytes = recv(fd, userBuffer, MAX_USERNAME + 1, MSG_NOSIGNAL);
		if(bytes < 0){
			return -1;
		}
		bytesReceived += bytes;
		if (bytesWritten < bytesReceived){
			if(bytesWritten == 0){
				ulen = userBuffer[bytesWritten++];
				printf("ULEN: %c ", ulen);
				if(ulen < 0){
					return -1;
				}
			}
			else{
				if(ulen > 0){
					username[bytesWritten - 1] = userBuffer[bytesWritten];
					bytesWritten++;
					ulen--;
				}
				else{
					username[bytesWritten - 1] = '\0';
					memset(userBuffer, 0, bytesWritten);
					memset(username, 0, bytesWritten);
					bytesWritten = 0;
					ucount--;
					printf("USERNAME: %s\n", username);
				}
			}
		}
	}  
    return 0;
}