#include "sha_256.h"
#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Helper to convert a 64-bit integer to Big-Endian bytes
static void uint64_to_big_endian(uint64_t val, uint8_t *bytes) {
  bytes[0] = (val >> 56) & 0xFF;
  bytes[1] = (val >> 48) & 0xFF;
  bytes[2] = (val >> 40) & 0xFF;
  bytes[3] = (val >> 32) & 0xFF;
  bytes[4] = (val >> 24) & 0xFF;
  bytes[5] = (val >> 16) & 0xFF;
  bytes[6] = (val >> 8) & 0xFF;
  bytes[7] = val & 0xFF;
}

static uint8_t *sha256_pad_message(const char *message, size_t msg_len,
                                   size_t *padded_len) {
  // 1. Calculate the new length.
  // We need room for: msg_len + 1 byte (0x80) + 8 bytes (length field)
  size_t min_len = msg_len + 1 + 8;

  // Find the next multiple of 64 bytes (512 bits)
  *padded_len = ((min_len + 63) / 64) * 64;

  // 2. Allocate the padded buffer (calloc ensures the rest is automatically
  // 0x00)
  uint8_t *padded_msg = (uint8_t *)calloc(1, *padded_len);
  if (!padded_msg)
    return NULL;

  // 3. Copy original message
  memcpy(padded_msg, message, msg_len);

  // 4. Append the '1' bit (0x80 byte) right after the message
  padded_msg[msg_len] = 0x80;

  // 5. Append original message length in BITS (bytes * 8) as a 64-bit
  // Big-Endian int
  uint64_t bits_len = (uint64_t)msg_len * 8;
  uint64_to_big_endian(bits_len, &padded_msg[*padded_len - 8]);
  return padded_msg;
}

static uint32_t rightrotate(uint32_t inp, uint32_t rotate) {
  rotate = rotate % 32;
  if (rotate == 0)
    return inp;
  return (inp >> rotate) | (inp << (32 - rotate));
}

static uint32_t *sha256(const char *input, const size_t len) {
  size_t padded_len;
  const uint8_t *padded_message = sha256_pad_message(input, len, &padded_len);
  uint32_t h[8] = {H0, H1, H2, H3, H4, H5, H6, H7};
  uint32_t w[64];
  uint32_t var[8];

  for (int i = 0; i < padded_len;) {
    for (int j = 0; j < 16; j++) {
      w[j] = ((uint32_t)padded_message[i] << 24) |
             ((uint32_t)padded_message[i + 1] << 16) |
             ((uint32_t)padded_message[i + 2] << 8) |
             (uint32_t)padded_message[i + 3];
      i += 4;
    }
    for (int j = 16; j < 64; j++) {
      uint32_t s0 = rightrotate(w[j - 15], 7) ^ rightrotate(w[j - 15], 18) ^
                    (w[j - 15] >> 3);
      uint32_t s1 = rightrotate(w[j - 2], 17) ^ rightrotate(w[j - 2], 19) ^
                    (w[j - 2] >> 10);
      w[j] = w[j - 16] + s0 + w[j - 7] + s1;
    }

    for (int j = 0; j < 8; j++)
      var[j] = h[j];

    for (int j = 0; j < 64; j++) {
      uint32_t S1 = rightrotate(var[4], 6) ^ rightrotate(var[4], 11) ^
                    rightrotate(var[4], 25);
      uint32_t ch = (var[4] & var[5]) ^ (~var[4] & var[6]);
      uint32_t temp1 = var[7] + S1 + ch + k[j] + w[j];
      uint32_t S0 = rightrotate(var[0], 2) ^ rightrotate(var[0], 13) ^
                    rightrotate(var[0], 22);
      uint32_t maj = (var[0] & var[1]) ^ (var[0] & var[2]) ^ (var[1] & var[2]);
      uint32_t temp2 = S0 + maj;

      var[7] = var[6];
      var[6] = var[5];
      var[5] = var[4];
      var[4] = var[3] + temp1;
      var[3] = var[2];
      var[2] = var[1];
      var[1] = var[0];
      var[0] = temp1 + temp2;
    }
    for (int j = 0; j < 8; j++) {
      h[j] = h[j] + var[j];
    }
  }
  // Free the padded message buffer allocated by the padding function
  free(padded_message);
  uint32_t *hvec = (uint32_t *)malloc(8 * sizeof(uint32_t));
  memcpy(hvec, h, 8 * sizeof(uint32_t));
  return hvec;
}

char *sha256_encode(const char *input, const size_t len) {
  uint32_t *hvec = sha256(input, len);

  char *hex_output = (char *)malloc(65); // 64 chars + 1 null terminator
  if (!hex_output)
    return NULL;

  for (int i = 0; i < 8; i++) {
    sprintf(&hex_output[i * 8], "%08x", hvec[i]);
  }

  return hex_output;
}

void sha256_binary(const char *input, const size_t len, uint8_t *output) {
  uint32_t *hvec = sha256(input, len);
  if (!hvec)
    return;

  for (int i = 0; i < 8; i++) {
    output[i * 4 + 0] = (hvec[i] >> 24) & 0xFF;
    output[i * 4 + 1] = (hvec[i] >> 16) & 0xFF;
    output[i * 4 + 2] = (hvec[i] >> 8) & 0xFF;
    output[i * 4 + 3] = hvec[i] & 0xFF;
  }
}
