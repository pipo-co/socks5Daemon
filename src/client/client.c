
#include "buffer/buffer.h"
#include "client/clientCommandController.h"
#include "client/clientDefs.h"
#include "client/clientUtils.h"

#include <stdio.h> 		// fgets, printf
#include <errno.h>		
#include <string.h> 	// memset, memc
#include <stdint.h> 	
#include <stdlib.h> 	//atoi, exit
#include <arpa/inet.h>	// recv, send


static int new_ipv6_connection(struct in6_addr ip, in_port_t port) ;
static int new_ipv4_connection(struct in_addr ip, in_port_t port) ;
static void interactive_client(int fd);
static bool log_in(int fd);
static void print_help();

static CommandController controllers[COMMAND_COUNT];
static char *descriptions[COMMAND_COUNT];

int main(int argc, char *argv[]) {
		
	int fd;
	char * ip = "127.0.0.1";
	uint16_t port = 8080;
	if(argc == 3) {
		ip = argv[1];
		port = atol(argv[2]);
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
		exit(1);
	}

	if(fd == -1){
		perror("Connection error");
		exit(1);
	}

	if(log_in(fd)) {
		client_command_controller_init(controllers, descriptions);
		interactive_client(fd);
	}

	close(fd);

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
	char * newLine;
	printf("Insert username: (max 255 characters. Finisish with enter) ");
	char username[UINT8_STR_MAX_LENGTH];
	fgets(username, UINT8_STR_MAX_LENGTH, stdin);
	newLine = strchr(username, '\n');
	if(newLine){
		*newLine = '\0';
	}

	if(username[0] == '\0'){
		perror("Invalid username");
	}

	printf("Insert password: (max 255 characters. Finisish with enter) ");
	char password[UINT8_STR_MAX_LENGTH];
	fgets(password, UINT8_STR_MAX_LENGTH, stdin);
	newLine = strchr(password, '\n');
	if(newLine){
		*newLine = '\0';
	}


	if(password[0] == '\0'){
		perror("Invalid password");
	}

	uint8_t ulen = strlen(username);
	uint8_t plen = strlen(password);
	size_t index = 0;
	uint8_t authMessage[AUTH_MESSAGE_LENGTH];

	memset(authMessage, '\0', AUTH_MESSAGE_LENGTH);
	authMessage[index++] = PIPO_PROTOCOL_VERSION;
	authMessage[index++] = ulen;
	memcpy(authMessage + index, username, ulen);
	index += ulen;
	authMessage[index++] = plen;
	memcpy(authMessage + index, password, plen);
	index += plen;
	
	size_t bytesToSend = index;
	size_t bytesSent = 0;
	ssize_t writeBytes;

	do {
		writeBytes = send(fd, authMessage + bytesSent, bytesToSend - bytesSent, MSG_NOSIGNAL);

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
		readBytes = recv(fd, authAns + bytesRecieved, AUTH_RESPONSE_LENGTH - bytesRecieved, MSG_NOSIGNAL);
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
	uint8_t command;
	char firstChar;
	bool isUint;
	print_help();

	while(1) {
		
		command = client_read_uint_or_char("Insert new command: ", COMMAND_COUNT, &firstChar, &isUint);

		if(!isUint){
			if(firstChar == 'h'){
				print_help();
			}
			else if(firstChar == 'x'){
				return;
			}
		}
		else if(isUint && command < COMMAND_COUNT){
			printf("\n----------------------------------------\n");
			printf("Selected command: %s\n", descriptions[command]);
			if(controllers[command].sender(fd)){
				printf("----------------------------------------\n");
				if(!controllers[command].receiver(fd)){
					printf("Error ocurred receiving the request\n");
					return;
				}
			}
			else {
				printf("Error ocurred sending the request\n");
				return;
			}
			printf("----------------------------------------\n");
		}
	}
}

static void print_help(){

	printf("\n----------------------------------------\n");
	printf("Client help\n");
	printf("----------------------------------------\n");
	printf("In order to get this message again you must send 'h' as a command value\n");
	printf("In order to close the session send 'x' as a command value\n");

	for (size_t i = 0; i < COMMAND_COUNT; i++){
		printf("Command number: %lu. Desc: %s\n", (unsigned long)i, descriptions[i]);
	}
}
