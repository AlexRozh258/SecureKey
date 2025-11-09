#ifndef TOTP_ENGINE_H
#define TOTP_ENGINE_H

#include <stdint.h>
#include <time.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTP_DEFAULT_TIME_STEP 30
#define TOTP_DEFAULT_DIGITS 6
#define TOTP_DEFAULT_ALGORITHM SHA1

typedef enum {
    SHA1,
    SHA256,
    SHA512
} totp_algorithm_t;

typedef struct {
    uint8_t time_step;
    uint8_t digits;
    totp_algorithm_t algorithm; 
} totp_config_t;

uint32_t totp_generate(const uint8_t* key, size_t key_len, 
                      time_t timestamp, const totp_config_t* config);

uint32_t totp_generate_current(const uint8_t* key, size_t key_len, 
                              const totp_config_t* config);

int totp_verify(const uint8_t* key, size_t key_len, 
               time_t timestamp, uint32_t code, 
               const totp_config_t* config, int window);

int totp_decode_base32(const char* base32_str, uint8_t* key, size_t key_len);

int totp_encode_base32(const uint8_t* key, size_t key_len, char* output, size_t output_len);

int totp_generate_secret(uint8_t* key, size_t key_len);

int totp_generate_secret_base32(char* output, size_t output_len, size_t key_bits);

int totp_generate_otpauth_url(char* buffer, size_t buffer_size,
                             const char* secret, const char* issuer,
                             const char* account_name, const totp_config_t* config);

uint8_t totp_get_time_remaining(time_t timestamp, const totp_config_t* config);

time_t totp_current_time(void);
uint64_t totp_calculate_time_step(time_t timestamp, uint8_t time_step);

#ifdef __cplusplus
}
#endif

#endif 