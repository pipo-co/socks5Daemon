include sourcePaths.inc
include Makefile.inc

INCLUDE= -I$(PWD)

SERVER=socks5d
CLIENT=client
CLIENT_SOURCES=client

# SOURCE_FILES = $(wildcard $(SOURCE_PATHS)/*.c)
SOURCE_FILES = $(foreach dir, $(SOURCE_PATHS), $(wildcard $(dir)/*.c))
CLIENT_SOURCE_FILES = $(foreach dir, $(CLIENT_SOURCES), $(wildcard $(dir)/*.c))
OBJECTS = $(patsubst %.c, %.o, $(SOURCE_FILES))
CLIENT_OBJECTS = $(patsubst %.c, %.o, $(CLIENT_SOURCE_FILES))

all: $(SERVER) $(CLIENT)


clean: 
	rm -rf $(OBJECTS) $(SERVER) $(CLIENT)

$(SERVER): server.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@

$(CLIENT): $(CLIENT_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ 

.PHONY: all clean