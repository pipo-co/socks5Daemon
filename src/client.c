#include <arpa/inet.h>
#include <netinet/in.h> 
#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define BUFSIZE 512
#define STDIN 0

void handleStdIn(int sock);
void handleSocket(int sock);

int new_ipv6_socket(char *ip, uint16_t port);
int new_ipv4_socket(char *ip, uint16_t port);

int main(int argc, char *argv[]) {
		
	// int sock = new_ipv6_socket("2800:3f0:4002:80d::200e", 80);
	fd_set fds;
	int sock = new_ipv4_socket("127.000.000.001", 80);

	while (1) {
		FD_SET(STDIN, &fds);
		FD_SET(sock, &fds);

		select(sock + 1, &fds, NULL, NULL, NULL);

		if(FD_ISSET(STDIN, &fds))
			handleStdIn(sock);
		
		if(FD_ISSET(sock, &fds))
			handleSocket(sock);
	}

	close(sock);
	return 0;
}

void handleStdIn(int sock) {

	char buffer[BUFSIZE];
	ssize_t readBytes = read(STDIN, buffer, BUFSIZE - 1);
	for (size_t i = 0; i < readBytes; i++) {
		// buffer[i] -= '0';
	}
	
	ssize_t numBytes = send(sock, buffer, readBytes, 0);
	if (numBytes < 0 || numBytes != readBytes)
        exit(1);
}

void handleSocket(int sock) {
	// Receive the same string back from the server
	ssize_t numBytes;
	char buffer[BUFSIZE]; 
	/* Receive up to the buffer size (minus 1 to leave space for a null terminator) bytes from the sender */
	numBytes = recv(sock, buffer, BUFSIZE - 1, 0);
	if (numBytes < 0) {
		exit(1);
	}  
	else if (numBytes == 0)
		exit(1);
	else {
		buffer[numBytes] = '\0';    // Terminate the string!
	}
	printf("Recieved: %s", buffer);
}

int new_ipv6_socket(char *ip, uint16_t port) {
	
	int sock;
	struct sockaddr_in6 addr; 
  
    // socket create and varification 
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); 
    if (sock == -1) { 
        perror("new_ipv6_socket: socket creation failed."); 
        exit(0); 
    } 
    
	bzero(&addr, sizeof(addr)); 

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port); 
	inet_pton(AF_INET6, ip, &addr.sin6_addr);

	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0) { 
        perror("new_ipv6_socket: connection with the server failed."); 
        exit(0); 
    } 

	return sock;
}

int new_ipv4_socket(char *ip, uint16_t port) {
	
	int sock;
	struct sockaddr_in addr; 
  
    // socket create and varification 
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (sock == -1) { 
        perror("new_ipv4_socket: socket creation failed."); 
        exit(0); 
    } 
    
	bzero(&addr, sizeof(addr)); 

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port); 
	inet_pton(AF_INET, ip, &addr.sin_addr.s_addr);

	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) != 0) { 
        printf("new_ipv4_socket: connection with the server failed."); 
        exit(0); 
    } 

	return sock;
}
