
#CC=clang scan-build -disable-checker deadcode.DeadStores -o /tmp/out  make
#complexity   --histogram --score  `find -name '*.c'` 2> /dev/null
INCLUDE = -I ./selector -I ./socks5 -I ./hello -I ./request -I ./buffer -I ./auth -I ./connect

CC=gcc
LIBRARIES=-lcheck -lrt -lpthread -lm -lsubunit
CFLAGS= -pthread -D_POSIX_C_SOURCE=200112L -Wall -pedantic -std=c11 $(INCLUDE) 

all: main 

clean: 
	rm -rf */*.o

main: main.c ./selector/selector.o ./socks5/socks5.o ./buffer/buffer.o ./request/request.o ./hello/hello.o ./auth/auth.o ./connect/connect.o
	$(CC) $(CFLAGS) $^ -o $@ 
