#ifndef UTILITIES_H
#define UTILITIES_H

#include <stddef.h>

int check_password_strength(const char* password);

int generate_random_password(char* output, size_t output_len, int length);

int read_password_secure(const char* prompt, char* password, size_t max_len);

#endif
