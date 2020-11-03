
all: tests server

server:
	cd src; make;

tests:
	cd test; make;

clean:
	cd test; make clean;
	cd src; make clean;