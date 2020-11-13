
#include <stdbool.h>		// bool
#include <stdint.h>			// uint
#include <stdio.h>			// fgets
#include <stdlib.h>			// strtoul
#include <sys/types.h>		// send & recv
#include <sys/socket.h>		// send & recv
#include <errno.h>			// errno
#include <string.h>			// memset

#include "client/clientReceivers.h"
#include "client/clientDefs.h"

static bool receiver_uint8(int fd);
static bool receiver_uint16(int fd);
static bool receiver_uint32(int fd);
static bool receiver_uint64(int fd);
static bool receiver_user_list(int fd);


// Modifications
bool add_user_receiver(int fd){
	return receiver_uint8(fd);
}

bool remove_user_receiver(int fd){
	return receiver_uint8(fd);
}

bool toggle_password_spoofing_receiver(int fd){
	return receiver_uint8(fd);
}

bool toggle_connection_clean_up_receiver(int fd){
	return receiver_uint8(fd);
}

bool set_buffer_size_receiver(int fd){
	return receiver_uint8(fd);
}

bool set_selector_timeout_receiver(int fd){
	return receiver_uint8(fd);
}

bool set_connection_timeout_receiver(int fd){
	return receiver_uint8(fd);
	
}

// Queries
bool list_users_receiver(int fd){
	return receiver_user_list(fd);
}

bool current_connections_receiver(int fd){
	return receiver_uint16(fd);
}


bool total_historic_connections_receiver(int fd){
	return receiver_uint64(fd);
}

bool max_concurrent_conections_receiver(int fd){
	return receiver_uint16(fd);
}

bool total_bytes_sent_receiver(int fd){
	return receiver_uint64(fd);
}

bool total_bytes_received_receiver(int fd){
	return receiver_uint64(fd);
}

bool connected_users_receiver(int fd){
	return receiver_uint8(fd);
}

bool total_user_count_receiver(int fd){
	return receiver_uint8(fd);
}

bool buffer_sizes_receiver(int fd){
	return receiver_uint32(fd);
}

bool selector_timeout_receiver(int fd){
	return receiver_uint8(fd);
}

bool connection_timeout_receiver(int fd){
	return receiver_uint8(fd);
}

bool user_total_current_connections_receiver(int fd){
	return receiver_uint16(fd);
}

static bool receiver_uint8(int fd) {
	ssize_t bytes;
	uint16_t bytesReceived = 0;
	uint16_t bytesWritten = 0;
	uint8_t buffer[UINT8_LENGTH];
	uint8_t type, command = 0xFF;
      
    do {
		bytes = recv(fd, buffer + bytesReceived, UINT8_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
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
						printf("TYPE: 0x%X ", type);
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("TYPE: %X ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("CMD: 0x%X ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: 0x%X\n", buffer[bytesWritten]);
					return true;
				}
				else {
					printf("RESPONSE: 0x%X\n", buffer[bytesWritten++]);
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
	ssize_t bytes;
	uint16_t bytesReceived = 0;
	uint16_t bytesWritten = 0;
	uint16_t response = 0;
	uint8_t buffer[UINT16_LENGTH];
	uint8_t type, command = 0xFF;
      
    do {
		bytes = recv(fd, buffer + bytesReceived, UINT16_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
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
						printf("TYPE: 0x%X ", type);
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("TYPE: 0x%X ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("CMD: 0x%X ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: %X\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response <<= 8;
					response += buffer[bytesWritten++];
					if(bytesWritten == UINT16_LENGTH){
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

	uint8_t buffer[UINT32_LENGTH];
	ssize_t bytes;
	uint16_t bytesReceived = 0;
	uint16_t bytesWritten = 0;
	
	uint8_t type, command = 0xFF;
	uint32_t response = 0;
      
    do {
		bytes = recv(fd, buffer + bytesReceived, UINT32_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
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
						printf("TYPE: 0x%X ", type);
						printf("CMD: 0x%X ", command);
						return true;
					}
					printf("TYPE: %X ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("CMD: %X ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: 0x%X\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response <<= 8;
					response += buffer[bytesWritten++];
					if(bytesWritten == UINT32_LENGTH){
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
	ssize_t bytes;
	uint16_t bytesReceived = 0;
	uint16_t bytesWritten = 0;
	uint8_t buffer[UINT64_LENGTH];
	uint8_t type, command = 0xFF;
	uint64_t response = 0;
      
    do {
		bytes = recv(fd, buffer + bytesReceived, UINT64_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
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
						printf("TYPE: 0x%X ", type);
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("TYPE: 0x%X ", type);
				}
				else if (bytesWritten == 1){
					command = buffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("CMD: 0x%X ", command);
				}
				else if (bytesWritten == 2 && command == 0xFE){
					printf("STATUS: 0x%X\n", buffer[bytesWritten]);
					return true;
				}
				else {
					response <<= 8;
					response += buffer[bytesWritten++];
					if(bytesWritten == UINT64_LENGTH){
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
    
    return true;
}

static bool receiver_user_list(int fd) {
	ssize_t bytes;
	uint16_t bytesReceived = 0;
	uint16_t bytesWritten = 0;
	uint8_t ucount = 0;
	uint8_t thirdVal = 0;
	char intialBuffer[NO_ARGS_LENGTH] = {0};
	char username[UINT8_STR_MAX_LENGTH] = {0};
	uint8_t type, command = 0xFF, ulen = 0;
	
	bool ulenFlag = true;

    do {
		bytes = recv(fd, intialBuffer + bytesReceived, NO_ARGS_LENGTH - bytesReceived, MSG_NOSIGNAL);
		
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
						printf("TYPE: 0x%X ", type);
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("TYPE: 0x%X ", type);
				}
				else {
					command = intialBuffer[bytesWritten++];
					if(command == 0xFF){
						printf("CMD: 0x%X\n", command);
						return true;
					}
					printf("CMD: 0x%X ", command);
				}
			}
		}
    } while(bytesReceived < NO_ARGS_LENGTH && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}

	bytes = recv(fd, &thirdVal, 1, MSG_NOSIGNAL);

	if(bytes == 0){
		printf("Connection closed\n");
		return false;
	}

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}
	
	if(command == 0xFE){
		printf("STATUS: %X\n", thirdVal);
		return true;
	}
	else{
		ucount = thirdVal;
	}
	if(ucount == 0){
		printf("UCOUNT %d\n", ucount);
		return true;
	}

	printf("UCOUNT %d\n", ucount);

	bytesReceived = 0;
	
	do{
		if(ulenFlag){
			bytes = recv(fd, &ulen, 1, MSG_NOSIGNAL);

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
			printf("USERNAME: %s ", username);
			memset(username, '\0', bytesReceived);		//reiniciar buffer de entrada
			ucount--;									//un usuario menos
			ulenFlag = true;							//volver a buscar el ulen
			bytesReceived = 0;							//reiniciar contador de bytes recibidos
		}	

		uint8_t priv;
		bytes = recv(fd, &priv, 1, MSG_NOSIGNAL);

		if(bytes == 0){
			printf("Connection closed\n");
			return false;
		}

		printf("PRIV 0x%X\n", priv);

	} while(ucount > 0 && (bytes != -1 || errno !=  EINTR));	

	if(bytes == -1) {
		perror("Connection interrupted\n");
		return false;
	}

   return true;
}
