
#CC=clang scan-build -disable-checker deadcode.DeadStores -o /tmp/out  make
#complexity   --histogram --score  `find -name '*.c'` 2> /dev/null
INCLUDE = -I ./selector -I ./socks5 -I ./hello -I ./request -I ./buffer -I ./auth -I ./connect -I ./stateMachine

CC=gcc
CFLAGS= -pthread -D_POSIX_C_SOURCE=200112L -ggdb -Wall -Wextra -pedantic -std=c11 -fsanitize=address -fno-omit-frame-pointer $(INCLUDE) 

all: main 
	$(CC) $(CFLAGS) client.c -o client

clean: 
	rm -rf */*.o
	rm main
	rm client

main: main.c ./selector/selector.o ./socks5/socks5.o ./buffer/buffer.o
	$(CC) $(CFLAGS) $^ -o $@ 
