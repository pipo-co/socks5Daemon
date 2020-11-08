CC=gcc
CFLAGS= -pthread -D_POSIX_C_SOURCE=200112L -ggdb -Wall -Wextra -Wno-implicit-fallthrough -Wno-unused-parameter -pedantic -std=c11 -fsanitize=address -fno-omit-frame-pointer $(INCLUDE) 

#CC=clang scan-build -disable-checker deadcode.DeadStores -o /tmp/out  make
#complexity   --histogram --score  `find -name '*.c'` 2> /dev/null