#include "hashing/sha_256.h"
#include "utils/base64Url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * This library generates jwt tokens.
 * JWT looks like following.
 * xx<header>xxx.yyy<payload>yyy.zzz<signature>zzz
 *
 * HEADER: This contains 2 parts
 *  {
 *      "alg": "HS256",
 *      "typ": "JWT"
 *  }
 *  The algorithm being used can be HS256, RSA or SHA256. This is the signing
 *  algorithm.
 *  The second value is the type of the token. This is JWT.
 *
 *  Then this JSON is encoded using base64url encoding to get the first part of
 *  the JSON.
 *
 * PAYLOAD: This is the second part that contians the claims.
 * See here for more details:
 * https://www.jwt.io/introduction#what-is-json-web-token-structure
 *
 * SIGNATURE: This makes sure that the payload wasn't changed along the way. We
 * take the header and the payload and sign it using the algorithm.
 */

// Standard base64 alphabet.

char *sign(const char *header, const char *payload, char *secret) {
  size_t max_enc_header_len = 4 * ((strlen(header) + 2) / 3);
  size_t max_enc_payload_len = 4 * ((strlen(payload) + 2) / 3);

  size_t combined_buffer_size = max_enc_payload_len + max_enc_header_len + 2;
  char *header_payload = (char *)malloc(combined_buffer_size);
  char *header_ptr = header_payload;

  char *encoded_header =
      base64_url_encode((unsigned const char *)header, strlen(header));
  size_t enc_header_len = strlen(encoded_header);
  memcpy(header_ptr, encoded_header, enc_header_len);
  free(encoded_header);
  header_ptr[enc_header_len] = '.';

  char *payload_ptr = header_ptr + enc_header_len + 1;
  char *encoded_payload =
      base64_url_encode((unsigned const char *)payload, strlen(payload));
  size_t enc_payload_len = strlen(encoded_payload);
  memcpy(payload_ptr, encoded_payload, enc_payload_len);

  size_t secret_len = strlen(secret);
  char *signature =
      sha256_encode(header_ptr, enc_header_len + 1 + enc_payload_len);
  printf("%s\n", signature);
  return NULL;
}

int main() {
  char *jwt = sign("{\"alg\":\"HS256\"}", "{\"user\":\"admin\"}", "secret_key");
  printf("%s\n", jwt);

  return 0;
}
