CC ?= clang
CFLAGS += -pthread -D_POSIX_C_SOURCE=200112L -ggdb -Wall -Wextra -pedantic -std=c11 -fsanitize=address -fno-omit-frame-pointer 

# muted warnings
CFLAGS += -Wno-unused-parameter -Wno-implicit-fallthrough

#CC=clang scan-build -disable-checker deadcode.DeadStores -o /tmp/out  make
#complexity   --histogram --score  `find -name '*.c'` 2> /dev/null