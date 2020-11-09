
#include "client/clientReceivers.h"
#include <stdbool.h>

#define NO_ARGS_LENGTH 2
#define UINT8_LENGTH 3
#define UINT16_LENGTH 4
#define UINT32_LENGTH 6
#define UINT64_LENGTH 10
#define MAX_USERNAME 255

static bool receiver_uint8(int fd);
static bool receiver_uint16(int fd);
static bool receiver_uint32(int fd);
static bool receiver_uint64(int fd);
static bool receiver_user_list(int fd);

void add_user_receiver(int fd){
	return receiver_uint8(fd);
}

void remove_user_receiver(int fd){
	return receiver_uint8(fd);
}

void toggle_password_spoofing_receiver(int fd){
	return receiver_uint8(fd);
}

void toggle_connection_clean_up_receiver(int fd){
	return receiver_uint8(fd);
}

void set_buffer_size_receiver(int fd){
	return receiver_uint8(fd);
}

void set_selector_timeout_receiver(int fd){
	return receiver_uint8(fd);
}

void set_connection_timeout_receiver(int fd){
	return receiver_uint8(fd);
	
}

void list_users_receiver(int fd){
	return receiver_user_list(fd);
}

void total_historic_connections_receiver(int fd){
	return receiver_uint64(fd);
}

void max_concurrent_conections_receiver(int fd){
	return receiver_uint16(fd);
}

void total_bytes_sent_receiver(int fd){
	return receiver_uint64(fd);
}

void total_bytes_received_receiver(int fd){
	return receiver_uint64(fd);
}

void connected_users_receiver(int fd){
	return receiver_uint64(fd);
}

void user_count_receiver(int fd){
	return receiver_uint8(fd);
}

void buffer_sizes_receiver(int fd){
	return receiver_uint32(fd);
}

void selector_timeout_receiver(int fd){
	return receiver_uint8(fd);
}

void connection_timeout_receiver(int fd){
	return receiver_uint8(fd);
}

void user_total_concurrent_connections_receiver(int fd){
	return receiver_uint8(fd);
}

static bool receiver_uint8(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	char buffer[UINT8_LENGTH];
	char type, command, response;
      
    do {
		bytes = recv(fd, buffer, UINT8_LENGTH - bytesWritten, MSG_NOSIGNAL);
		
		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}
		if(bytes > 0){
			bytesReceived += bytes;
			while(bytesWritten < bytesReceived){
				if( bytesWritten == 0){
					type = buffer[bytesWritten++];
					if(type == 0xFF){
						printf("TYPE: %c ", type);
						printf("CMD: %c\n", type);
						return true;
					}
					printf("TYPE: %c ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: %c\n", command);
						return true;
					}
					printf("CMD: %c ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: %c\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response = buffer[bytesWritten++];
					printf("RESPONSE: %c\n", command);
				}
			}
		}	
    } while(bytesReceived < UINT8_LENGTH  && (bytes != -1 || errno !=  EINTR));
    
	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}

    return true;
}

static bool receiver_uint16(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	char buffer[UINT16_LENGTH];
	uint16_t type, command, response;
      
    do {
		bytes = recv(fd, buffer, UINT16_LENGTH - bytesWritten, MSG_NOSIGNAL);
		
		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}
		if(bytes > 0){
			bytesReceived += bytes;
			while(bytesWritten < bytesReceived){
				if( bytesWritten == 0){
					type = buffer[bytesWritten++];
					if(type == 0xFF){
						printf("TYPE: %c ", type);
						printf("CMD: %c\n", type);
						return true;
					}
					printf("TYPE: %c ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: %c\n", command);
						return true;
					}
					printf("CMD: %c ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: %c\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response = (buffer[bytesWritten++] >> ((UINT16_LENGTH - bytesWritten)* 8)) & 0xFF;
					if(bytesReceived == UINT32_LENGTH){
						printf("RESPONSE: %u\n", response);
					}
				}
			}
		}	
    } while(bytesReceived < UINT16_LENGTH  && (bytes != -1 || errno !=  EINTR));
    
	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}

    return true;
}

static bool receiver_uint32(int fd) {

	char buffer[UINT32_LENGTH];

	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	
	uint16_t type, command;
	uint32_t response;
      
    do {
		bytes = recv(fd, buffer, UINT32_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}

		if(bytes > 0){
			bytesReceived += bytes;
			while(bytesWritten < bytesReceived){
				if(bytesWritten == 0){
					type = buffer[bytesWritten++];
					if(type == 0xFF){
						printf("TYPE: %c ", type);
						printf("CMD: %c ", type);
						return true;
					}
					printf("TYPE: %c ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: %c\n", command);
						return true;
					}
					printf("CMD: %c ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: %c\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response = (buffer[bytesWritten++] >> ((UINT32_LENGTH - bytesWritten)* 8)) & 0xFF;
					if(bytesReceived == UINT32_LENGTH){
						printf("RESPONSE: %u\n", response);
					}
				}
			}
		}	
    } while(bytesReceived < UINT32_LENGTH  && (bytes != -1 || errno !=  EINTR));
	
	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}
    
    return true;
}

static bool receiver_uint64(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	char buffer[UINT64_LENGTH];
	uint16_t type, command;
	uint32_t response;
      
    do {
		bytes = recv(fd, buffer, UINT64_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}

		if(bytes > 0){
			bytesReceived += bytes;
			while(bytesWritten < bytesReceived){
				if(bytesWritten == 0){
					type = buffer[bytesWritten++];
					if(type == 0xFF){
						printf("TYPE: %c ", type);
						printf("CMD: %c\n", type);
						return true;
					}
					printf("TYPE: %c ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: %c\n", command);
						return true;
					}
					printf("CMD: %c ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: %c\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response = (buffer[bytesWritten++] >> ((UINT64_LENGTH - bytesWritten)* 8)) & 0xFF;
					if(bytesReceived == UINT64_LENGTH){
							printf("RESPONSE: %lu\n", response);
						}
				}
			}

		}	
    } while(bytesReceived < UINT64_LENGTH  && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}
    
    return 0;
}

static bool receiver_user_list(int fd) {
	uint16_t bytes, bytesReceived = 0;
	uint16_t bytesWritten = 0;
	uint16_t ucount, thirdVal = 0, ulen = 0;
	char intialBuffer[NO_ARGS_LENGTH];
	char username[MAX_USERNAME] = {0};
	uint16_t type, command;
	
	bool ulenFlag = true;
	
      
    do {
		bytes = recv(fd, intialBuffer, NO_ARGS_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}
		
		if(bytes > 0){
			bytesReceived += bytes;
			while(bytesWritten < bytesReceived){
				if(bytesWritten == 0){
					type = intialBuffer[bytesWritten++];
					if(type == 0xFF){
						printf("TYPE: %c ", type);
						printf("CMD: %c\n", type);
						return true;
					}
					printf("TYPE: %c ", type);
				}
				else {
					command = intialBuffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: %c\n", command);
						return true;
					}
					printf("CMD: %c ", command);
				}
			}
		}
    } while(bytesReceived < NO_ARGS_LENGTH && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}

	bytes = recv(fd, thirdVal, 1, MSG_NOSIGNAL);


	if(bytes == 0){
		printf("Connection closed\n");
		return false;
	}

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}
	
	if(command == 0xFE){
		printf("STATUS: %c\n", thirdVal);
	}
	else{
		ucount = thirdVal;
	}
	if(ucount == 0){
		printf("UCOUNT %d\n", ucount);
		return true;
	}
	printf("UCOUNT %d", ucount);

	bytesWritten = bytesReceived = 0;
	
	do{
		if(ulenFlag){
			bytes = recv(fd, ulen, 1, MSG_NOSIGNAL);

			if(bytes == 0){
				printf("Connection closed\n");
				return false;
			}

			if(bytes == -1) {
				perror("Connection interrupted\n");
				return false;
			}

			if(bytes > 0){
				ulenFlag = false;
				if(ulen == 0){
					printf("ULEN %d\n", ulen);
					return true;
				}
				printf("ULEN %d ", ulen);
			}
		}
		
		bytes = recv(fd, username + bytesReceived, ulen - bytesReceived, MSG_NOSIGNAL);

		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}

		if(bytes > 0){
			bytesReceived += bytes;
		}

		if(bytesReceived == ulen){
			username[bytesReceived] = '\0'; //aprovecho a poner el 0, imprimir y limpiar el buffer de username 
			printf("USERNAME: %s", username);
			memset(username, '\0', bytesReceived);		//reiniciar buffer de entrada
			ucount--;									//un usuario menos
			ulenFlag = true;							//volver a buscar el ulen
			bytesReceived = 0;							//reiniciar contador de bytes recibidos
		}		
	} while(ucount > 0 && (bytes != -1 || errno !=  EINTR));	

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}

   return 0;
}

