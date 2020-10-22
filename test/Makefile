EXEC=test

SOURCES=main.c

CC=gcc
LIBRARIES=-lcheck -lrt -lpthread -lm -lsubunit
CFLAGS= -Wall -pedantic -std=c99 -I../src -ggdb -fsanitize=address -fno-omit-frame-pointer


all: compile run clean

compile: $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $(EXEC) $(LIBRARIES)

run:
	./$(EXEC)

clean:
	rm -f $(EXEC)

.PHONY: all, run, clean