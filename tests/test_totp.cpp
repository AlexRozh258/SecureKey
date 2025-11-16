#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/totp_engine.h"

void test_base32_encoding() {
    printf("Testing Base32 Encoding/Decoding\n");
    
    const char* test_secret = "JBSWY3DPEHPK3PXP";
    unsigned char key[32];
    int key_len = base32_decode(test_secret, key, sizeof(key));
    
    printf("Base32 secret: %s\n", test_secret);
    printf("Decoded key length: %d bytes\n", key_len);
    assert(key_len > 0);
    
    char encoded[64];
    int enc_len = base32_encode(key, key_len, encoded, sizeof(encoded));
    printf("Re-encoded: %s\n", encoded);
    assert(strcmp(test_secret, encoded) == 0);
    (void)enc_len;
    
    printf("Base32 tests passed\n\n");
}

void test_secret_generation() {
    printf("Testing Secret Generation\n");
    
    char base32_secret[64];
    assert(generate_totp_secret(base32_secret, sizeof(base32_secret)) == 0);
    printf("Generated Base32 secret: %s\n", base32_secret);
    
    unsigned char decoded_key[32];
    int decoded_len = base32_decode(base32_secret, decoded_key, sizeof(decoded_key));
    assert(decoded_len > 0);
    
    printf("Secret generation tests passed\n\n");
}

void test_totp_generation() {
    printf("Testing TOTP Generation\n");
    
    const char* test_secret = "JBSWY3DPEHPK3PXP";

    uint32_t code = generate_totp(test_secret);
    printf("TOTP: %06u\n", code);
    assert(code != 0);
    
    assert(code < 1000000);
    
    printf("TOTP generation basic functionality passed\n\n");
}

void test_totp_validation() {
    printf("Testing TOTP Validation\n");
    
    const char* test_secret = "JBSWY3DPEHPK3PXP";
    
    uint32_t valid_code = generate_totp(test_secret);
    
    int result = validate_totp(test_secret, valid_code);
    printf("Valid code %06u validation: %s\n", valid_code, result ? "PASS" : "FAIL");
    assert(result == 1);
    
    result = validate_totp(test_secret, 123456);
    printf("Invalid code validation: %s\n", result ? "FAIL" : "PASS");
    assert(result == 0);
    
    printf("TOTP validation tests passed\n\n");
}

int main() {
    printf("Starting TOTP Engine Tests...\n\n");
    
    test_base32_encoding();
    test_secret_generation();
    test_totp_generation();
    test_totp_validation();
    
    printf("All TOTP tests passed successfully\n");
    
    return 0;
}