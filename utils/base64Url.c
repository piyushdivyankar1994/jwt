#include "base64Url.h"
#include <stdlib.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_url_encode(unsigned const char *input, size_t input_len) {
  size_t output_len = 4 * ((input_len + 2) / 3);
  char *output = (char *)malloc(output_len);
  if (!output)
    return NULL;

  size_t i = 0, j = 0;
  while (i < input_len) {
    uint32_t octet_a = i < input_len ? input[i++] : 0;
    uint32_t octet_b = i < input_len ? input[i++] : 0;
    uint32_t octet_c = i < input_len ? input[i++] : 0;

    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
    output[j++] = b64_table[(triple >> 18) & 0x3F];
    output[j++] = b64_table[(triple >> 12) & 0x3F];
    output[j++] = b64_table[(triple >> 6) & 0x3F];
    output[j++] = b64_table[triple & 0x3F];
  }

  size_t rem = input_len % 3;
  if (rem == 2)
    j -= 2;
  else if (rem == 1)
    j -= 1;
  output[j] = '\0';

  // Convert standard Base64 chars to Base64URL chars (+ -> -, / -> _)
  for (int i = 0; output[i] != '\0'; i++) {
    if (output[i] == '+')
      output[i] = '-';
    else if (output[i] == '/')
      output[i] = '_';
  }
  return output;
}

static char base64_char_value(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '-')
    return 62;
  if (c == '_')
    return 63;
  return -1;
}

char *base64_url_decode(const unsigned char *input, size_t input_len) {
  size_t output_len = 3 * ((input_len + 3) / 4);
  char *output = (char *)malloc(output_len + 1);

  size_t i = 0, j = 0;
  while (i < input_len) {
    int count = 0;
    uint32_t combination = 0;
    for (int k = 0; k < 4; k++) {
      if (i < input_len) {
        int val = base64_char_value(input[i++]);
        if (val >= 0) {
          combination = (combination << 6) | val;
          count++;
        }
      }
    }
    if (count >= 2)
      output[j++] = (combination >> (16 - (4 - count) * 6)) & 0xFF;
    if (count >= 3)
      output[j++] = (combination >> (8 - (4 - count) * 6)) & 0xFF;
    if (count == 4)
      output[j++] = combination & 0xFF;
  }
  output[j] = '\0';
  return output;
}
