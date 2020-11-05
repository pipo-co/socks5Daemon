include sourcePaths.inc
include Makefile.inc

INCLUDE= -I$(PWD)

SERVER=server
CLIENT=client

# SOURCE_FILES = $(wildcard $(SOURCE_PATHS)/*.c)
SOURCE_FILES = $(foreach dir, $(SOURCE_PATHS), $(wildcard $(dir)/*.c))
OBJECTS = $(patsubst %.c, %.o, $(SOURCE_FILES))

all: $(SERVER)

clean: 
	rm -rf $(OBJECTS) $(SERVER) $(CLIENT)

$(SERVER): server.c $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o main

$(CLIENT): client.c
	$(CC) $(CFLAGS) $^ -o $@ 

.PHONY: all clean