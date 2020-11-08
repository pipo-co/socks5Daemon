#ifndef LOGGER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define LOGGER_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include "selector/selector.h"

void logger_init(FdSelector s);

void logger_non_blocking_log(int fd, char *log, size_t nbytes);

#endif