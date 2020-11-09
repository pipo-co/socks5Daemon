
#define _POSIX_C_SOURCE 200112L

#include "buffer/buffer.h"

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

#define BUFSIZE 512
#define COMMAND_COUNT 18
#define STDIN 0
#define NO_ARGS_LENGTH 2
#define UINT8_LENGTH 3
#define UINT32_LENGTH 6
#define UINT64_LENGTH 10
#define MAX_STR_LEN 255
#define MAX_USERNAME 255
#define FULL_USER_MAX_SIZE 513

#define CREDENTIALS_LENGTH 256
#define AUTH_MESSAGE_LENGTH 515
#define AUTH_RESPONSE_LENGTH 2
#define PIPO_PROTOCOL_VERSION 1

void handleStdIn(int sock);
void handleSocket(int sock);

static int new_ipv6_connection(struct in6_addr ip, in_port_t port) ;
static int new_ipv4_connection(struct in_addr ip, in_port_t port) ;
static void interactive_client(int fd);
static void print_help();

typedef struct CommandController {
	void (*sender)(int);
	void (*receiver)(int);	
} CommandController;

CommandController controllers[COMMAND_COUNT];

int main(int argc, char *argv[]) {
		
	fd_set fds;
	int fd;
	char * ip = "127.0.0.1";
	uint16_t port = 8080;

	if(argc == 3) {
		ip = argv[2];
		port = atoi(argv[3]);
	}

	struct in_addr addr4;
	struct in6_addr addr6;

	if(inet_pton(AF_INET, ip, &addr4)){
		fd = new_ipv4_connection(addr4, htons(port));
	}
	else if(inet_pton(AF_INET6, ip, &addr6)){
		fd = new_ipv6_connection(addr6, htons(port));
	}
	else {
		perror("The provided IP address is invalid.");
	}

	if(!log_in(fd)) {
		return 1;
	}

	interactive_client(fd);

	// Close

	return 0;
}

static int new_ipv6_connection(struct in6_addr ip, in_port_t port) {
	
	int sock;
	struct sockaddr_in6 addr; 
  
    // socket create and varification 
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP); 
    if (sock == -1) { 
        return -1;
    } 
    
	memset(&addr, '\0', sizeof(addr)); 

    addr.sin6_family = AF_INET;
    addr.sin6_port = port; 
	addr.sin6_addr = ip;

	int ans;

	do {
		ans = connect(sock, (struct sockaddr*) &addr, sizeof(addr));
	}while(ans == -1 && errno != EINTR);
	
	if(ans == -1) {  
        close(sock);
		return -1;
    } 

	return sock;
}

static int new_ipv4_connection(struct in_addr ip, in_port_t port) {
	
	int sock;
	struct sockaddr_in addr; 
  
    // socket create and varification 
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP); 
    if (sock == -1) { 
        return -1;
    } 
    
	memset(&addr, '\0', sizeof(addr)); 

    addr.sin_family = AF_INET;
    addr.sin_port = port; 
	addr.sin_addr = ip;

	int ans;

	do {
		ans = connect(sock, (struct sockaddr*) &addr, sizeof(addr));
	}while(ans == -1 && errno != EINTR);
	
	if(ans == -1) {  
        close(sock);
		return -1;
    } 

	return sock;
}

static bool log_in(int fd) {

	size_t i;
	uint8_t ulen;
	uint8_t plen;
	
	printf("Insert username: (max 255 characters. Finisish with enter)");
	char username[CREDENTIALS_LENGTH];
	for (i = 0; i < CREDENTIALS_LENGTH && username[i] != '\n'; i++) {
		username[i] = getchar();
		ulen++;
	}
	username[i] = '\0';

	if(username[0] == '\0'){
		perror("Invalid username");
	}

	printf("Insert password: (max 255 characters. Finisish with enter)");
	char password[CREDENTIALS_LENGTH];
	for (i = 0; i < CREDENTIALS_LENGTH && password[i] != '\n'; i++) {
		password[i] = getchar();
		plen++;
	}
	password[i] = '\0';

	if(password[0] == '\0'){
		perror("Invalid password");
	}

	uint8_t authMessage[AUTH_MESSAGE_LENGTH];
	memset(authMessage, '\0', AUTH_MESSAGE_LENGTH);
	authMessage[0] = PIPO_PROTOCOL_VERSION;
	authMessage[1] = ulen;
	strcpy(authMessage, username);
	authMessage[ulen + 2] = plen;
	strcpy(authMessage, password);
	
	size_t bytesToSend = ulen + plen + 3;
	size_t bytesSent = 0;
	ssize_t writeBytes;

	do {
		writeBytes = write(fd, authMessage + bytesSent, bytesToSend - bytesSent);

		if(writeBytes > 0){
			bytesSent += writeBytes;
		}

	} while (bytesSent < bytesToSend && (writeBytes != -1 || errno !=  EINTR));

	if(writeBytes == -1){
		perror("Error sending auth");
	}

	uint8_t authAns[AUTH_RESPONSE_LENGTH];
	ssize_t readBytes;
	size_t bytesRecieved = 0;

	do {
		readBytes = read(fd, authAns + bytesRecieved, AUTH_RESPONSE_LENGTH - bytesRecieved);
		if(readBytes > 0){
			bytesRecieved += readBytes;
		}
	} while (bytesRecieved < AUTH_RESPONSE_LENGTH && (readBytes != -1 || errno !=  EINTR));

	if(readBytes == -1){
		perror("Error reading auth response");
	}

	// Auth successful
	if(authAns[1] == 0x00) {
		printf("Logged in succesfully\n");
		return true;
	}

	// Auth Unsuccessful
	else {
		close(fd);
		printf("Error ocurred during log in: ");

		if(authAns[1] == 0x01){
			printf("Authentication failed.\n");
		}
		else if(authAns[1] == 0x02){
			printf("Invalid version.\n");
		}
		else {
			printf("Unexpected answer\n");
		}
		return false;
	}

}

static void interactive_client(int fd) {

	while(1) {

		print_help();
		
		char command;
		printf("Insert new command: ");

		// TODO: getchar() ?? - Tobi
		scanf("%1c", &command);

		if(command == 'x') {
			break;
		}

		command -= 'a';

		controllers[command].sender(fd);

		controllers[command].receiver(fd);
	}
}

void list_users_sender(int fd){
	no_args_builder(fd, QUERY, LIST_USERS);
}

void total_historic_connections_sender(int fd){
	no_args_builder(fd, QUERY, TOTAL_CONNECTIONS);
}

void current_connections_sender(int fd){
	
}

void max_current_conections_sender(int fd){
	
}

void total_bytes_sent_sender(int fd){
	
}

void total_bytes_received_sender(int fd){
	
}

void connected_users_sender(int fd){
	
}

void user_count_sender(int fd){
	
}

void buffer_sizes_sender(int fd){
	
}

void selector_timeout_sender(int fd){
	
}

void connection_timeout_sender(int fd){
	
}

void user_total_concurrent_connections_sender(int fd){
	
	char user[CREDENTIALS_LENGTH];
	printf("Insert username: ");
	scanf("%255c", user);
	string_builder(fd, QUERY, TOTAL_CONCURRENT_CONECTON, user);
}

void add_user_sender(int fd){
	char user[CREDENTIALS_LENGTH];
	printf("Insert username: ");
	scanf("%255c", user);
	char pass[CREDENTIALS_LENGTH];
	printf("Insert password: ");
	scanf("%255c", pass);

	// Check privilege value (0 or 1)??
	char priv;
	printf("Insert privilege: ");
	scanf("%1c", &priv);

	new_user_builder(fd, MODIFICATION, NEW_USER, user, pass, priv);
}

void remove_user_sender(int fd){
	char user[CREDENTIALS_LENGTH];
	printf("Insert username: ");
	scanf("%255c", user);
	string_builder(fd, MODIFICATION, DELETE_USER, user);
}

void toggle_password_spoofing_sender(int fd){
	char toggle;
	printf("Insert argument: ");
	scanf("%1c", &toggle);
	uint8_builder(fd, MODIFICATION, TOGGLE_PASS, toggle);
}

void toggle_connection_clean_up_sender(int fd){

}

void set_buffer_size_sender(int fd){
	uint32_t buffSize;
	printf("Insert username: ");
	scanf("%u", &buffSize);
	uint32_builder(fd, MODIFICATION, TOGGLE_PASS, toggle);
}

void set_selector_timeout_sender(int fd){

}

void set_connection_timeout_sender(int fd){

}

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

/*
  * Sender -> generar paquete y enviarlo al server
  * - String
  * - No args
  * - uint8
  * - uint32
  * - User (string, string, uint8)  
  */

/*
  * Reciever -> recibir el paquete y parsearlo
  * - uint8
  * - uint32
  * - uint64
  * - User list
  */


int string_builder(int fd, uint8_t type, uint8_t command, char * string) {

	char message[MAX_STR_LEN + 3]; // type + command + strlen + string

	uint8_t strLen = (uint8_t) strlen(string);
	uint16_t messageLen = 3 + strLen;

	uint16_t bytes, bytesSent = 0;

	message[0] = type;
	message[1] = command;
	message[2] = strLen;
	memcpy(message + 3, string, strLen);

	do{
		bytes = send(fd, message, messageLen - bytesSent, MSG_NOSIGNAL);

		// Closed Connection
		if(bytes == 0) {
			return -1;
		}

		if(bytes > 0) {
			bytesSent += bytes;
		}

	} while(bytesSent < messageLen && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		return -1;
	}
	
	return 0;
}

int no_args_builder (int fd, uint8_t type, uint8_t command) {

	char message[NO_ARGS_LENGTH];

	uint8_t bytes, bytesSent = 0;

	message[0] = type;
	message[1] = command;

	do {
		bytes = send(fd, message, NO_ARGS_LENGTH - bytesSent, MSG_NOSIGNAL);

		// Closed Connection
		if(bytes == 0) {
			return -1;
		}

		if(bytes > 0) {
			bytesSent += bytes;
		}

	} while(bytesSent < NO_ARGS_LENGTH && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		return -1;
	}

	return 0;
}

int uint8_builder (int fd, uint8_t type, uint8_t command, uint8_t arg) {

	char message[UINT8_LENGTH];

	uint8_t bytes, bytesSent = 0;

	message[0] = type;
	message[1] = command;
	message[2] = arg;

	do {
		bytes = send(fd, message, UINT8_LENGTH - bytesSent, MSG_NOSIGNAL);
		
		// Closed Connection
		if(bytes == 0) {
			return -1;
		}

		if(bytes > 0) {
			bytesSent += bytes;
		}

	} while( bytesSent < UINT8_LENGTH && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		return -1;
	}

	return 0;
}

int uint32_builder (int fd, uint8_t type, uint8_t command, uint32_t arg) {

	char message[UINT32_LENGTH];

	uint8_t bytes, bytesSent = 0;

	message[0] = type;
	message[1] = command;

	for(int i = 0; i < sizeof(uint32_t); i++) {
		message[i + 2] = (arg >> ((sizeof(uint32_t) - i - 1)* 8)) & 0xFF;
	}

	do {
		bytes = send(fd, message, UINT8_LENGTH - bytesSent, MSG_NOSIGNAL);

		// Closed Connection
		if(bytes == 0) {
			return -1;
		}

		if(bytes > 0) {
			bytesSent += bytes;
		}

	} while(bytesSent < UINT32_LENGTH && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		return -1;
	}

	return 0;
}

int user_builder(int fd, uint8_t type, uint8_t command, char * username, char * password, uint8_t privilege) {

	char message[FULL_USER_MAX_SIZE + 2];

	uint8_t ulen = strlen(username);
	uint8_t plen = strlen(password);

	uint16_t messageLen = 5 + ulen + plen; //1 x type, 1 x command, 1 privilege y 1 x length por cada string

	uint16_t bytes, bytesSent = 0;
	uint16_t i = 0;


	message[i++] = type;
	message[i++] = command;

	message[i++] = ulen;
	memcpy(message + i, username, ulen);
	i += ulen;

	message[i++] = plen;
	memcpy(message + i, password, plen);
	i += plen;

	message[i++] = privilege;

	do {
		bytes = send(fd, message, messageLen - bytesSent, MSG_NOSIGNAL);

		// Closed Connection
		if(bytes == 0) {
			return -1;
		}

		if(bytes > 0) {
			bytesSent += bytes;
		}

	} while(bytesSent < messageLen && (bytes != -1 || errno !=  EINTR));

	if(bytes == -1) {
		return -1;
	}
	
	return 0;
}

int receiver_uint8(int fd) {
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

int receiver_uint32(int fd){

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

int receiver_uint64(int fd){
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

int receiver_user_list(int fd){
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