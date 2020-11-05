#include <stdlib.h>
// Source: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

void build_decoding_table();

void base64_cleanup();