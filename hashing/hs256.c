#include "sha_256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
void hmac_sha256(const char *key, const size_t key_len, const uint8_t *msg,
                 const size_t msg_len, uint8_t *out_digest) {
  // Step 1: Prepare the key. It must be exactly 64 bytes (the block size).
  uint8_t paddedKey[64] = {0};
  if (key_len > BLOCK_SIZE) {
    sha256_binary(key, key_len, paddedKey);
  } else {
    memcpy(paddedKey, key, key_len);
  }
  // Step 2: Create the inner and outer padded keys using XOR
  uint8_t ipad[BLOCK_SIZE];
  uint8_t opad[BLOCK_SIZE];

  for (int i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5C;
  }
  // Step 3: Inner Hash = SHA256(ipad || msg)
  uint8_t buffer[BLOCK_SIZE + msg_len];
  memcpy(buffer, ipad, BLOCK_SIZE);
  memcpy(buffer + BLOCK_SIZE, msg, msg_len);
  uint8_t innnerHash[SHA256_DIGEST_SIZE];
  sha256_binary(buffer, BLOCK_SIZE + msg_len, innnerHash);

  uint8_t outerbuffer[BLOCK_SIZE + SHA256_DIGEST_SIZE];
  memcpy(outerbuffer, opad, BLOCK_SIZE);
  memcpy(outerbuffer + BLOCK_SIZE, innnerHash, SHA256_DIGEST_SIZE);
  sha256_binary(outerbuffer, BLOCK_SIZE + SHA256_DIGEST_SIZE, out_digest);
}

char *hs256_encode(const char *input, const size_t len, const char *secret,
                   const size_t slen) {
  uint8_t output[32];
  hmac_sha256(secret, slen, (const uint8_t *)input, len, output);

  char *hex_output = (char *)malloc(65);
  if (!hex_output)
    return NULL;

  for (int i = 0; i < 32; i++) {
    sprintf(&hex_output[i * 2], "%02x", output[i]);
  }
  hex_output[64] = '\0';
  return hex_output;
}
