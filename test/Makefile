include filesNotTested.inc
include ../Makefile.inc

EXEC=test

SOURCES=main.c

CFLAGS += -I../src

LIBRARIES = -lcheck -lrt -lpthread -lm -lsubunit

all: compile run

compile: $(SOURCES) $(FILES_NOT_TESTED)
	$(CC) $(CFLAGS) $^ -o $(EXEC) $(LIBRARIES) 

run:
	./$(EXEC)

clean:
	rm -f $(EXEC)

.PHONY: all, run, clean