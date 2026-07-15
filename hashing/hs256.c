#include "sha_256.h"
#include <string.h>

#define BLOCK_SIZE 64
void hmac_sha256(const char *key, const size_t key_len, const uint8_t *msg,
                 const size_t msg_len, uint8_t *out_digest) {
  // Step 1: Prepare the key. It must be exactly 64 bytes (the block size).
  uint8_t paddedKey[64] = {0};
  if (key_len > BLOCK_SIZE) {
    sha256_binary(key, key_len, paddedKey);
  } else {
    memcpy(paddedKey, key, 64);
  }
  // Step 2: Create the inner and outer padded keys using XOR
  uint8_t ipad[BLOCK_SIZE];
  uint8_t opad[BLOCK_SIZE];

  for (int i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5C;
  }
  // Step 3: Inner Hash = SHA256(ipad || msg)
  // Step 4: Outer Hash = SHA256(opad || Inner Hash)
  // Final result is the 32-byte HS256 signature
}
