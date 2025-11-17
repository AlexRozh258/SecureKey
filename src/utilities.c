#include "utilities.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

// Check password strength and return score
int check_password_strength(const char* password) {
    if (!password || strlen(password) == 0) {
        return -1;
    }

    int length = strlen(password);
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;

    for (int i = 0; i < length; i++) {
        if (password[i] >= 'a' && password[i] <= 'z') has_lower = 1;
        else if (password[i] >= 'A' && password[i] <= 'Z') has_upper = 1;
        else if (password[i] >= '0' && password[i] <= '9') has_digit = 1;
        else has_special = 1;
    }

    // Calculate score: length component + character variety
    int score = (length >= 12 ? 2 : length >= 8 ? 1 : 0) +
                has_lower + has_upper + has_digit + has_special;

    return score;
}

// Generate a random password
int generate_random_password(char* output, size_t output_len, int length) {
    if (!output || output_len == 0 || length < 8 || length > 64) {
        return -1;
    }

    if ((size_t)length + 1 > output_len) {
        return -1;
    }

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

    FILE* urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        return -1;
    }

    for (int i = 0; i < length; i++) {
        unsigned char byte;
        if (fread(&byte, 1, 1, urandom) != 1) {
            fclose(urandom);
            return -1;
        }
        output[i] = charset[byte % (sizeof(charset) - 1)];
    }
    output[length] = '\0';

    fclose(urandom);
    return 0;
}

// Read password securely from terminal (no echo)
int read_password_secure(const char* prompt, char* password, size_t max_len) {
    struct termios old_term, new_term;

    if (!password || max_len == 0) {
        return -1;
    }

    printf("%s", prompt);
    fflush(stdout);

    // Disable echo
    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        return -1;
    }

    new_term = old_term;
    new_term.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
        return -1;
    }

    // Read password
    char* result = fgets(password, max_len, stdin);

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");

    if (result == NULL) {
        return -1;
    }

    // Remove newline
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }

    return 0;
}
