#include "crypto_engine.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#define KEY_LEN 32
#define SALT_LEN 16
#define IV_LEN 16

static unsigned char global_salt[SALT_LEN];

int crypto_init(void) {
    return RAND_bytes(global_salt, SALT_LEN) == 1 ? 0 : -1;
}

int crypto_cleanup(void) {
    secure_cleanup(global_salt, SALT_LEN);
    return 0;
}

int derive_key(const char* password, unsigned char* key) {
    return PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        global_salt, SALT_LEN,
        100000, EVP_sha256(),
        KEY_LEN, key
    ) == 1 ? 0 : -1;
}

int encrypt_data(const unsigned char* plaintext, size_t len,
                 const unsigned char* key, unsigned char* ciphertext) {
    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int out_len, final_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(ciphertext, iv, IV_LEN);

    if (EVP_EncryptUpdate(ctx, ciphertext + IV_LEN, &out_len, plaintext, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + IV_LEN + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return out_len + final_len + IV_LEN;
}

int decrypt_data(const unsigned char* ciphertext, size_t len,
                 const unsigned char* key, unsigned char* plaintext) {
    if (len < IV_LEN) return -1;

    unsigned char iv[IV_LEN];
    memcpy(iv, ciphertext, IV_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int out_len, final_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext + IV_LEN, len - IV_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return out_len + final_len;
}

void secure_cleanup(void* data, size_t len) {
    if (data && len > 0) {
        memset(data, 0, len);
    }
}
