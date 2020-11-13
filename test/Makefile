include filesNotTested.inc

EXEC=test

SOURCES=main.c

CC = gcc
LIBRARIES = -lcheck -lrt -lpthread -lm -lsubunit
CFLAGS = -Wall -pedantic -std=c99 -I../src -ggdb -fsanitize=address -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200112L 

FILES_NOT_TESTED_OBJECTS = $(patsubst %.c, %.o, $(FILES_NOT_TESTED))

all: compile run clean

compile: $(SOURCES) $(FILES_NOT_TESTED_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $(EXEC) $(LIBRARIES) 

run:
	./$(EXEC)

clean:
	rm -f $(EXEC)

.PHONY: all, run, clean