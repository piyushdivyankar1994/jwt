#include <cstdint>
#include <stddef.h>
#include <stdint.h>
#ifndef HS256_H

void hmac_sha256(const uint8_t *key, const size_t key_len, const uint8_t *msg,
                 const size_t msg_len, uint8_t *out_digest);

#endif
