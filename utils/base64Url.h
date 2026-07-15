

#ifndef BASE64_URL_H
#include <stddef.h>
char *base64_url_encode(unsigned const char *input, size_t input_len);
char *base64_url_decode(const unsigned char *input, size_t input_len);
#endif
