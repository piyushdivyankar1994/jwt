#ifndef SHA256_H
#define SHA256_H
#include <stddef.h>
#include <stdint.h>
char *sha256_encode(const char *input, const size_t len);
uint8_t *sha256_binary(const char *input, const size_t len, uint8_t *output);
#endif
