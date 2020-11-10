#ifndef BASE_64_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5
#define BASE_64_H_a7f0b7011d5bc49decb646a7852c4531c07e17b5

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BASE64_ENCODE_SIZE(len) (4*((len)/3) + 4)

#define BASE64_DECODE_SIZE(len) (3*((len)/4) + 4)

size_t base64_encode(uint8_t in[], size_t len, char out[], bool trail);

size_t base64_decode(char in[], uint8_t out[]);

#endif