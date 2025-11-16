#include "totp_engine.h"

void example_usage() {
    char secret_base32[64];
    if (totp_generate_secret_base32(secret_base32, sizeof(secret_base32), 160) == 0) {
        printf("Generated secret: %s\n", secret_base32);
    }
    
    uint8_t binary_secret[20];
    if (totp_generate_secret(binary_secret, sizeof(binary_secret)) == 0) {
        char display_secret[64];
        totp_encode_base32(binary_secret, sizeof(binary_secret), display_secret, sizeof(display_secret));
        printf("Binary secret in Base32: %s\n", display_secret);
    }
}