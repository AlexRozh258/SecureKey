#include <stdio.h>
#include <string.h>
#include "crypto_engine.h"
#include "vault_controller.h"
#include "totp_engine.h"

int main() {
    printf("SecureKey - Testing Crypto Engine and TOTP Engine\n\n");
    
    // Initialize crypto engine
    if (crypto_init() != 0) {
        printf("ERROR: Failed to initialize crypto engine\n");
        return 1;
    }
    printf("Crypto engine initialized\n");
    
    // Test crypto engine
    unsigned char key[32];
    if (derive_key("test_password", key) == 0) {
        printf("Crypto engine key derivation working\n");
    } else {
        printf("Crypto engine key derivation failed\n");
    }
    
    // Test encryption/decryption
    const char* plaintext = "Hello, SecureKey!";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    
    int cipher_len = encrypt_data((unsigned char*)plaintext, 17, key, ciphertext);
    if (cipher_len > 0) {
        printf("Encryption working (cipher length: %d bytes)\n", cipher_len);
        
        int decrypted_len = decrypt_data(ciphertext, cipher_len, key, decrypted);
        if (decrypted_len == 17 && memcmp(plaintext, decrypted, 17) == 0) {
            printf("Decryption working (decrypted: %s)\n", decrypted);
        } else {
            printf("Decryption failed\n");
        }
    } else {
        printf("Encryption failed\n");
    }
    
    printf("\nTesting TOTP Engine\n");
    
    // Generate a secret
    char secret[64];
    if (generate_totp_secret(secret, sizeof(secret)) == 0) {
        printf("Generated TOTP secret: %s\n", secret);
        
        // Generate TOTP code
        uint32_t code = generate_totp(secret);
        printf("Generated TOTP code: %06u\n", code);
        
        // Validate the code
        if (validate_totp(secret, code) == 0) {
            printf("TOTP validation working\n");
        } else {
            printf("TOTP validation failed\n");
        }
    } else {
        printf("Failed to generate TOTP secret\n");
    }
    
    // Test with known secret
    const char* known_secret = "JBSWY3DPEHPK3PXP";  // "Hello!" in Base32
    uint32_t known_code = generate_totp(known_secret);
    printf("TOTP code for '%s': %06u\n", known_secret, known_code);
    
    // Cleanup
    crypto_cleanup();
    printf("\nCrypto engine cleaned up\n");
    
    printf("\nAll basic tests completed\n");
    return 0;
}
