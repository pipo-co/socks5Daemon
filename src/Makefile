include sourcePaths.inc
include Makefile.inc

INCLUDE= -I$(PWD)

SERVER=socks5d
CLIENT=pipoClient
CLIENT_SOURCES=client

SOURCE_FILES = $(foreach dir, $(SOURCE_PATHS), $(wildcard $(dir)/*.c))
OBJECTS = $(patsubst %.c, %.o, $(SOURCE_FILES))

CLIENT_SOURCE_FILES = $(foreach dir, $(CLIENT_SOURCES), $(wildcard $(dir)/*.c))
CLIENT_OBJECTS = $(patsubst %.c, %.o, $(CLIENT_SOURCE_FILES))

all: $(SERVER) $(CLIENT)

clean: 
	rm -rf $(OBJECTS) $(SERVER) $(CLIENT_OBJECTS) $(CLIENT)

$(SERVER): server.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@

$(CLIENT): $(CLIENT_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ 

.PHONY: all clean