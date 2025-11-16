#ifndef TOTP_ENGINE_H
#define TOTP_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t generate_totp(const char* base32_secret);
int generate_totp_secret(char* output, size_t output_len);
int validate_totp(const char* base32_secret, uint32_t code);

int base32_decode(const char* encoded, unsigned char* result, size_t buf_len);
int base32_encode(const unsigned char* data, size_t len, char* result, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif