#include "totp_engine.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <time.h>
#include <string.h>

#define TOTP_TIME_STEP 30
#define TOTP_CODE_DIGITS 6

// Проста функція для обчислення степеня (замість math.h)
static uint32_t power10(int exponent) {
    uint32_t result = 1;
    for (int i = 0; i < exponent; i++) {
        result *= 10;
    }
    return result;
}

// Спрощене декодування Base32 (без паддингу)
int base32_decode(const char* encoded, unsigned char* result, size_t buf_len) {
    if (!encoded || !result) return -1;
    
    const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t len = strlen(encoded);
    size_t output_size = (len * 5 + 7) / 8;
    
    if (output_size > buf_len) return -1;
    
    memset(result, 0, output_size);
    
    int buffer = 0, bits = 0;
    size_t count = 0;
    
    for (size_t i = 0; i < len; i++) {
        char ch = encoded[i];
        const char* p = strchr(base32_chars, ch);
        if (!p) continue;  // Пропускаємо невалідні символи
        
        buffer = (buffer << 5) | (p - base32_chars);
        bits += 5;
        
        if (bits >= 8) {
            result[count++] = (buffer >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    
    return count;
}

// Спрощене кодування Base32 (без паддингу)
int base32_encode(const unsigned char* data, size_t len, char* result, size_t buf_len) {
    if (!data || !result) return -1;
    
    const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t output_size = (len * 8 + 4) / 5;
    
    if (output_size + 1 > buf_len) return -1;
    
    memset(result, 0, buf_len);
    
    int buffer = data[0];
    int bits = 8;
    size_t count = 0;
    size_t index = 1;
    
    while (bits > 0 || index < len) {
        if (bits < 5) {
            if (index < len) {
                buffer = (buffer << 8) | data[index++];
                bits += 8;
            } else {
                break;
            }
        }
        
        int value = (buffer >> (bits - 5)) & 0x1F;
        bits -= 5;
        result[count++] = base32_chars[value];
    }
    
    return count;
}

// Спрощена генерація TOTP
uint32_t generate_totp(const char* base32_secret) {
    if (!base32_secret) return 0;
    
    unsigned char secret[32];
    int secret_len = base32_decode(base32_secret, secret, sizeof(secret));
    if (secret_len <= 0) return 0;
    
    // Таймстеп
    uint64_t time_steps = (uint64_t)time(NULL) / TOTP_TIME_STEP;
    
    // Конвертація в big-endian
    unsigned char time_bytes[8];
    for (int i = 7; i >= 0; i--) {
        time_bytes[i] = time_steps & 0xFF;
        time_steps >>= 8;
    }
    
    // HMAC-SHA1
    unsigned char hmac[20];
    unsigned int hmac_len;
    HMAC(EVP_sha1(), secret, secret_len, time_bytes, 8, hmac, &hmac_len);
    
    // Dynamic truncation
    int offset = hmac[hmac_len - 1] & 0x0F;
    uint32_t code = ((hmac[offset] & 0x7F) << 24) |
                   (hmac[offset + 1] << 16) |
                   (hmac[offset + 2] << 8) |
                   hmac[offset + 3];
    
    // 6-значний код
    uint32_t totp_code = code % power10(TOTP_CODE_DIGITS);
    
    memset(secret, 0, sizeof(secret));
    return totp_code;
}

// Спрощена генерація секрету
int generate_totp_secret(char* output, size_t output_len) {
    if (!output || output_len < 17) return -1;  // 16 символів + null
    
    unsigned char random_bytes[10];  // 10 байт = 16 Base32 символів
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return -1;
    }
    
    int result = base32_encode(random_bytes, sizeof(random_bytes), output, output_len);
    memset(random_bytes, 0, sizeof(random_bytes));
    
    return result > 0 ? 0 : -1;
}

// Спрощена валідація
int validate_totp(const char* base32_secret, uint32_t code) {
    if (!base32_secret) return -1;
    
    // Перевіряємо поточний код
    if (generate_totp(base32_secret) == code) {
        return 0;
    }
    
    // Спрощена перевірка попереднього інтервалу
    time_t old_time = time(NULL) - TOTP_TIME_STEP;
    uint64_t old_steps = (uint64_t)old_time / TOTP_TIME_STEP;
    
    unsigned char secret[32];
    int secret_len = base32_decode(base32_secret, secret, sizeof(secret));
    if (secret_len <= 0) return -1;
    
    unsigned char time_bytes[8];
    for (int i = 7; i >= 0; i--) {
        time_bytes[i] = old_steps & 0xFF;
        old_steps >>= 8;
    }
    
    unsigned char hmac[20];
    unsigned int hmac_len;
    HMAC(EVP_sha1(), secret, secret_len, time_bytes, 8, hmac, &hmac_len);
    
    int offset = hmac[hmac_len - 1] & 0x0F;
    uint32_t old_code = ((hmac[offset] & 0x7F) << 24) |
                       (hmac[offset + 1] << 16) |
                       (hmac[offset + 2] << 8) |
                       hmac[offset + 3];
    
    uint32_t old_totp = old_code % power10(TOTP_CODE_DIGITS);
    
    memset(secret, 0, sizeof(secret));
    return (old_totp == code) ? 0 : -1;
}
