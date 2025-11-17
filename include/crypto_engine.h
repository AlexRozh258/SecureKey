#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <stddef.h>

#define KEY_LEN 32

int crypto_init(void);

int crypto_cleanup(void);

int derive_key(const char* password, unsigned char* key);

int derive_key_with_salt(const char* password, const unsigned char* salt, size_t salt_len, unsigned char* key);

int encrypt_data(const unsigned char* plaintext, size_t len,
                 const unsigned char* key, unsigned char* ciphertext);

int decrypt_data(const unsigned char* ciphertext, size_t len,
                 const unsigned char* key, unsigned char* plaintext);

void secure_cleanup(void* data, size_t len);

#endif
