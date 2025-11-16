#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <stddef.h>

#define KEY_LEN 32

// Initialize crypto engine (must be called before use)
int crypto_init(void);

// Cleanup crypto engine
int crypto_cleanup(void);

// Derive encryption key from password using PBKDF2
int derive_key(const char* password, unsigned char* key);

// Encrypt data using AES-256-CBC
int encrypt_data(const unsigned char* plaintext, size_t len,
                 const unsigned char* key, unsigned char* ciphertext);

// Decrypt data using AES-256-CBC
int decrypt_data(const unsigned char* ciphertext, size_t len,
                 const unsigned char* key, unsigned char* plaintext);

// Securely wipe sensitive data from memory
void secure_cleanup(void* data, size_t len);

#endif
