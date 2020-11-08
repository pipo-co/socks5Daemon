
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
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#define BUFSIZE 512
#define COMMAND_COUNT 18
#define STDIN 0

#define CREDENTIALS_LENGTH 256
#define AUTH_MESSAGE_LENGTH 512
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
	void (*reciever)(int);	
} CommandController;

CommandController controllers[COMMAND_COUNT];



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

	if(!log_in(fd)){
		return -1;
	}

	interactive_client(fd);


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
		ans = connect(sock, (struct sockaddr*) &addr, sizeof(addr);
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
		ans = connect(sock, (struct sockaddr*) &addr, sizeof(addr);
	}while(ans == -1 && errno != EINTR);
	
	if(ans == -1) {  
        close(sock);
		return -1;
    } 

	return sock;
}

static bool log_in(int fd) {
	
	printf("Insert username: (max 255 characters. Finisish with enter)");
	char username[CREDENTIALS_LENGTH];
	for (size_t i = 0; i < CREDENTIALS_LENGTH; i++) {
		username[i] = getchar();
		if(username[i] == '\n'){
			username[i] = '\0';
		}
	}

	if(strlen(username) == 0){
		perror("Invalid username");
	}

	printf("Insert password: (max 255 characters. Finisish with enter)");
	char password[CREDENTIALS_LENGTH];
	for (size_t i = 0; i < CREDENTIALS_LENGTH; i++) {
		password[i] = getchar();
		if(password[i] == '\n'){
			password[i] = '\0';
		}
	}
	if(strlen(password) == 0){
		perror("Invalid username");
	}

	uint8_t ulen = (uint8_t) strlen(username);
	uint8_t plen = (uint8_t) strlen(password);

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

	if(writeBytes == -1 && errno != EINTR){
		perror("Error sending auth");
	}

	char authAns[AUTH_RESPONSE_LENGTH];
	ssize_t readBytes;
	size_t bytesRecieved = 0;
	do {
		readBytes = read(fd, authMessage + bytesRecieved, AUTH_RESPONSE_LENGTH - bytesRecieved);
		if(readBytes > 0){
			bytesRecieved += readBytes;
		}
	} while (bytesRecieved < AUTH_RESPONSE_LENGTH && (readBytes != -1 || errno !=  EINTR));

	if(writeBytes == -1 && errno != EINTR){
		perror("Error sending auth");
	}

	if(authAns[1] == 0){
		printf("Logged in succesfully\n");
		return true;
	}
	else {
		close(fd);
		printf("Error ocurred during log in: ");
		if(authAns[1] == '0x01'){
			printf("Authentication failed.\n");
		}
		else if(authAns[1] == '0x02'){
			printf("Invalid version.\n");
		}
		else {
			printf("Unexpected answer\n");
		}
		return false;
	}

}

static void interactive_client(int fd) {

	while (1) {

		print_help();
		
		char command;
		printf("Insert new command: ");
		scanf("%1c", &command);

		if(command == 'x'){
			break;
		}
		command -= 'a';

		controllers[command].sender(fd);

		controllers[command].reciever(fd);
	}
}

void list_users_sender(int fd){
	no_args_builder(fd, QUERY, LIST_USERS);
}

void total_historic_connections_sender(int fd){
	no_args_builder(fd, QUERY, TOTAL_CONNECTIONS)
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
	char priv;
	printf("Insert privilige: ");
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
