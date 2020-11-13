#ifndef CLIENT_UTILS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_UTILS_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

#include <stdint.h>
#include <stdbool.h>

uint64_t client_read_uint(char * message, uint64_t max);

uint64_t client_read_uint_or_char(char *message, uint64_t max, char * firstChar, bool *isUint);

#endif
