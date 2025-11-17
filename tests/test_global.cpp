#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include "arg_parse.h"
#include "crypto_engine.h"
#include "vault_controller.h"
#include "totp_engine.h"

extern "C" {
    #include "arg_parse.h"
    #include "crypto_engine.h"
    #include "vault_controller.h"
    #include "totp_engine.h"
    
    int check_password(const char* password);
    int generate_password(int length, int show);
}

class SecureKeyTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto_init();
        snprintf(vault_path, sizeof(vault_path), "/tmp/test_vault_%d.vault", getpid());
    }

    void TearDown() override {
        vault_cleanup();
        crypto_cleanup();
        remove(vault_path);
    }

    char vault_path[256];
};


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}