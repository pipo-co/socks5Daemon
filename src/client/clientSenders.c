#include <stdint.h>
#include <stdio.h>			// fgets
#include <stdlib.h>			// strtoul
#include <sys/types.h>		// send & recv
#include <sys/socket.h>		// send & recv
#include <errno.h>			// send & recv

#include "client/clientSenders.h"
#include "client/clientDefs.h"

#define NO_ARGS_LENGTH 2
#define UINT8_LENGTH 3
#define UINT32_LENGTH 6
#define UINT64_LENGTH 10
#define MAX_STR_LEN 255
#define MAX_USERNAME 255
#define FULL_USER_MAX_SIZE 513
#define CREDENTIALS_LENGTH 256
#define UINT8_BASE_10_SIZE 4
#define UINT32_BASE_10_SIZE 11

static bool no_args_builder (int fd, uint8_t type, uint8_t command);
static bool uint8_builder (int fd, uint8_t type, uint8_t command, uint8_t arg);
static bool uint32_builder (int fd, uint8_t type, uint8_t command, uint32_t arg);
static bool user_builder(int fd, uint8_t type, uint8_t command, char * username, char * password, uint8_t privilege);
static bool string_builder(int fd, uint8_t type, uint8_t command, char * string);


bool list_users_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_LIST_USERS);
}

bool total_historic_connections_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_TOTAL_HISTORIC_CONNECTIONS);
}

bool current_connections_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_CURRENT_CONNECTIONS);
}

bool max_current_conections_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_MAX_CURRENT_CONECTIONS);
}

bool total_bytes_sent_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_TOTAL_BYTES_SENT);
}

bool total_bytes_received_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_TOTAL_BYTES_RECEIVED);
}

bool connected_users_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_CONNECTED_USERS);
}

bool user_count_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_USER_COUNT);
}

bool buffer_sizes_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_BUFFER_SIZES);
}

bool selector_timeout_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_SELECTOR_TIMEOUT);
}

bool connection_timeout_sender(int fd){
	return no_args_builder(fd, CT_QUERY, CQ_CONNECTION_TIMEOUT);
}

bool user_total_concurrent_connections_sender(int fd){
	
	char user[CREDENTIALS_LENGTH];
	printf("Insert username: ");
	fgets(user, CREDENTIALS_LENGTH, stdin);
	return string_builder(fd, CT_QUERY, CQ_USER_TOTAL_CONCURRENT_CONNECTIONS, user);
}

bool add_user_sender(int fd){
	
	char user[CREDENTIALS_LENGTH];
	printf("Insert username: ");
	fgets(user, CREDENTIALS_LENGTH, stdin);

	char pass[CREDENTIALS_LENGTH];
	printf("Insert password: ");
	fgets(pass, CREDENTIALS_LENGTH, stdin);

	// Check privilege value (0 or 1)??
	char priv;
	printf("Admin privilege?: [y/n] ");
	priv = getchar();
	while(getchar() != '\n');

	priv = (priv == 'y' || priv == 'Y');

	return user_builder(fd, CT_MODIFICATION, CM_ADD_USER, user, pass, priv);
}

bool remove_user_sender(int fd){
	
	char user[CREDENTIALS_LENGTH];
	printf("Insert username: ");
	fgets(user, CREDENTIALS_LENGTH, stdin);
	return string_builder(fd, CT_MODIFICATION, CM_REMOVE_USER, user);
}

bool toggle_password_spoofing_sender(int fd){
	
	char toggle;
	printf("Password sniffing active?: [y/n] ");
	toggle = getchar();
	while(getchar() != '\n');

	toggle = (toggle == 'y' || toggle == 'Y');

	return uint8_builder(fd, CT_MODIFICATION, CM_TOGGLE_PASSWORD_SPOOFING, toggle);
}

bool toggle_connection_clean_up_sender(int fd){
	
	char toggle;
	printf("Connection clean up active?: [y/n] ");
	toggle = getchar();
	while(getchar() != '\n');

	toggle = (toggle == 'y' || toggle == 'Y');

	return uint8_builder(fd, CT_MODIFICATION, CM_TOGGLE_CONNECTION_CLEAN_UN, toggle);
}

bool set_buffer_size_sender(int fd){
	
	char size[UINT32_BASE_10_SIZE];
	printf("Insert new buffer size: ");
	fgets(size, UINT32_BASE_10_SIZE, stdin);
	uint32_t size32 = strtoul(size, NULL, 10);
	return uint32_builder(fd, CT_MODIFICATION, CM_SET_BUFFER_SIZE, size32);
	
}

bool set_selector_timeout_sender(int fd){
	
	char timeout[UINT8_BASE_10_SIZE];
	printf("Insert new selector timeout: ");
	fgets(timeout, UINT8_BASE_10_SIZE, stdin);
	uint8_t timeout8 = strtoul(timeout, NULL, 10);
	return uint32_builder(fd, CT_MODIFICATION, CM_SET_SELECTOR_TIMEOUT, timeout8);
}

bool set_connection_timeout_sender(int fd){
	
	char timeout[UINT8_BASE_10_SIZE];
	printf("Insert new selector timeout: ");
	fgets(timeout, UINT8_BASE_10_SIZE, stdin);
	uint8_t timeout8 = strtoul(timeout, NULL, 10);
	return uint32_builder(fd, CT_MODIFICATION, CM_SET_CONNECTION_TIMEOUT, timeout8);
}

static bool string_builder(int fd, uint8_t type, uint8_t command, char * string) {

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

static bool no_args_builder (int fd, uint8_t type, uint8_t command) {

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

static bool uint8_builder (int fd, uint8_t type, uint8_t command, uint8_t arg) {

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

static bool uint32_builder (int fd, uint8_t type, uint8_t command, uint32_t arg) {

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

static bool user_builder(int fd, uint8_t type, uint8_t command, char * username, char * password, uint8_t privilege) {

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
