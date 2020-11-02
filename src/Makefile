
#CC=clang scan-build -disable-checker deadcode.DeadStores -o /tmp/out  make
#complexity   --histogram --score  `find -name '*.c'` 2> /dev/null
INCLUDE = -I ./selector -I ./socks5 -I ./hello -I ./request -I ./buffer -I ./auth -I ./connect

CC=gcc
CFLAGS= -pthread -D_POSIX_C_SOURCE=200112L -ggdb -Wall -Wextra -pedantic -std=c11 -fsanitize=address -fno-omit-frame-pointer $(INCLUDE) 

all: main 
	$(CC) $(CFLAGS) client.c -o client

clean: 
	rm -rf */*.o

main: main.c ./selector/selector.o ./socks5/socks5.o ./buffer/buffer.o ./request/request.o ./hello/hello.o ./auth/auth.o ./connect/connect.o
	$(CC) $(CFLAGS) $^ -o $@ 
