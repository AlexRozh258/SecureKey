#include "totp_engine.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <stddef.h> 

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char base32_padding = '=';


uint32_t totp_generate(const uint8_t* key, size_t key_len, 
                      time_t timestamp, const totp_config_t* config) {
    if (!key || !config) return 0;
    
    uint64_t time_step = totp_calculate_time_step(timestamp, config->time_step);
    
    uint8_t time_bytes[8];
    for (int i = 7; i >= 0; i--) {
        time_bytes[i] = (time_step >> (8 * (7 - i))) & 0xFF;
    }
    
    uint8_t hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    
    const EVP_MD* md = NULL;
    switch (config->algorithm) {
        case SHA1:
            md = EVP_sha1();
            break;
        case SHA256:
            md = EVP_sha256();
            break;
        case SHA512:
            md = EVP_sha512();
            break;
        default:
            md = EVP_sha1();
    }
    
    if (!HMAC(md, key, (int)key_len, time_bytes, sizeof(time_bytes), hmac_result, &hmac_len)) {
        return 0;
    }
    
    int offset = hmac_result[hmac_len - 1] & 0x0F;

    uint32_t binary_code = 
        ((hmac_result[offset] & 0x7F) << 24) |
        (hmac_result[offset + 1] << 16) |
        (hmac_result[offset + 2] << 8) |
        (hmac_result[offset + 3]);
    
    uint32_t modulus = 1;
    for (int i = 0; i < config->digits; i++) {
        modulus *= 10;
    }
    
    return binary_code % modulus;
}


int totp_generate_secret(uint8_t* key, size_t key_len) {
    if (!key || key_len < 10) { 
        return -1;
    }
    

    if (RAND_bytes(key, (int)key_len) != 1) {
        return -1;
    }
    
    return 0;
}

int totp_generate_secret_base32(char* output, size_t output_len, size_t key_bits) {
    if (!output) {
        return -1;
    }
    
    size_t key_len = (key_bits + 7) / 8;
    
    if (key_len < 10) key_len = 10;
    if (key_len > 32) key_len = 32;
    
    size_t min_base32_len = ((key_len * 8) + 4) / 5;
    min_base32_len = (min_base32_len + 7) / 8 * 8 + 1;
    
    if (output_len < min_base32_len) {
        return -1;
    }
    
    uint8_t key[32];
    if (totp_generate_secret(key, key_len) != 0) {
        return -1;
    }
    
    int result = totp_encode_base32(key, key_len, output, output_len);
    if (result < 0) {
        return -1;
    }
    
    return 0;
}

uint32_t totp_generate_current(const uint8_t* key, size_t key_len, 
                              const totp_config_t* config) {
    time_t now = totp_current_time();
    return totp_generate(key, key_len, now, config);
}

int totp_verify(const uint8_t* key, size_t key_len, 
               time_t timestamp, uint32_t code, 
               const totp_config_t* config, int window) {
    if (!key || !config) return 0;
    

    if (totp_generate(key, key_len, timestamp, config) == code) {
        return 1;
    }
    

    for (int i = -window; i <= window; i++) {
        if (i == 0) continue;
        
        time_t test_time = timestamp + (i * config->time_step);
        if (totp_generate(key, key_len, test_time, config) == code) {
            return 1;
        }
    }
    
    return 0;
}


int totp_decode_base32(const char* base32_str, uint8_t* key, size_t key_len) {
    if (!base32_str || !key) return -1;
    
    size_t input_len = strlen(base32_str);
    size_t output_len = 0;

    size_t expected_len = (input_len * 5) / 8;
    if (expected_len > key_len) return -1;
    
    uint32_t buffer = 0;
    int bits_remaining = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        char c = base32_str[i];
        
        if (c == ' ' || c == base32_padding) continue;
        
        const char* pos = strchr(base32_alphabet, c);
        if (!pos) return -1;
        
        int value = pos - base32_alphabet;
        buffer = (buffer << 5) | value;
        bits_remaining += 5;
        
        if (bits_remaining >= 8) {
            bits_remaining -= 8;
            key[output_len++] = (buffer >> bits_remaining) & 0xFF;
        }
    }
    
    return (int)output_len;
}

int totp_encode_base32(const uint8_t* key, size_t key_len, char* output, size_t output_len) {
    if (!key || !output) return -1;
    
    size_t min_output_len = ((key_len * 8) + 4) / 5;
    min_output_len = (min_output_len + 7) / 8 * 8 + 1;
    
    if (output_len < min_output_len) {
        return -1;
    }
    
    size_t input_index = 0;
    size_t output_index = 0;
    uint32_t buffer = 0;
    int bits_remaining = 0;
    
    while (input_index < key_len || bits_remaining > 0) {
        if (bits_remaining < 5) {
            if (input_index < key_len) {
                buffer = (buffer << 8) | key[input_index++];
                bits_remaining += 8;
            } else {
                buffer <<= (5 - bits_remaining);
                bits_remaining = 5;
            }
        }
        
        bits_remaining -= 5;
        int value = (buffer >> bits_remaining) & 0x1F;
        output[output_index++] = base32_alphabet[value];
    }
    

    while (output_index % 8 != 0) {
        output[output_index++] = base32_padding;
    }
    
    output[output_index] = '\0';
    return (int)output_index;
}


uint8_t totp_get_time_remaining(time_t timestamp, const totp_config_t* config) {
    if (!config) return 0;
    
    uint64_t time_step = totp_calculate_time_step(timestamp, config->time_step);
    time_t next_step = (time_step + 1) * config->time_step;
    uint8_t remaining = (uint8_t)(next_step - timestamp);
    return (remaining <= config->time_step) ? remaining : 0;
}

time_t totp_current_time(void) {
    return time(NULL);
}


uint64_t totp_calculate_time_step(time_t timestamp, uint8_t time_step) {
    return timestamp / time_step;
}



int totp_generate_otpauth_url(char* buffer, size_t buffer_size,
                             const char* secret, const char* issuer,
                             const char* account_name, const totp_config_t* config) {

    (void)buffer;
    (void)buffer_size;
    (void)secret;
    (void)issuer;
    (void)account_name;
    (void)config;
    

    return -1;
}