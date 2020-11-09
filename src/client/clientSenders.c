#include <stdint.h>

#include "client/clientSenders.h"

#define NO_ARGS_LENGTH 2
#define UINT8_LENGTH 3
#define UINT32_LENGTH 6
#define UINT64_LENGTH 10
#define MAX_STR_LEN 255
#define MAX_USERNAME 255
#define FULL_USER_MAX_SIZE 513

static int no_args_builder (int fd, uint8_t type, uint8_t command);
static int uint8_builder (int fd, uint8_t type, uint8_t command, uint8_t arg);
static int uint32_builder (int fd, uint8_t type, uint8_t command, uint32_t arg);
static int user_builder(int fd, uint8_t type, uint8_t command, char * username, char * password, uint8_t privilege);
static int string_builder(int fd, uint8_t type, uint8_t command, char * string);

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

static int string_builder(int fd, uint8_t type, uint8_t command, char * string) {

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

static int no_args_builder (int fd, uint8_t type, uint8_t command) {

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

static int uint8_builder (int fd, uint8_t type, uint8_t command, uint8_t arg) {

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

static int uint32_builder (int fd, uint8_t type, uint8_t command, uint32_t arg) {

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

static int user_builder(int fd, uint8_t type, uint8_t command, char * username, char * password, uint8_t privilege) {

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
