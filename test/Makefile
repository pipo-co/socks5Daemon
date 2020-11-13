include filesNotTested.inc
include ../Makefile.inc

EXEC=test

SOURCES=main.c

CFLAGS += -I../src -lcheck -lrt -lpthread -lm -lsubunit

FILES_NOT_TESTED_OBJECTS = $(patsubst %.c, %.o, $(FILES_NOT_TESTED))

all: compile run clean

compile: $(SOURCES) $(FILES_NOT_TESTED)
	$(CC) $(CFLAGS) $^ -o $(EXEC) $(LIBRARIES) 

run:
	./$(EXEC)

clean:
	rm -f $(EXEC) $(FILES_NOT_TESTED_OBJECTS)

.PHONY: all, run, clean