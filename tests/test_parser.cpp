#include <gtest/gtest.h>
#include <cstring>

extern "C" {
    #include "arg_parse.h"
}

class ArgParseTest : public ::testing::Test {
protected:
    arguments_t args;
    
    void SetUp() override {
        memset(&args, 0, sizeof(args));
    }
};

TEST_F(ArgParseTest, ParseCommandsWithoutRequiredArgs) {
    struct TestCase {
        const char* argv[10];
        int argc;
        command_t expected_command;
    } test_cases[] = {
        {{"securekey", "list"}, 2, CMD_LIST},
        {{"securekey", "ls"}, 2, CMD_LIST},
        {{"securekey", "generate"}, 2, CMD_GENERATE},
        {{"securekey", "gen"}, 2, CMD_GENERATE},
        {{"securekey", "init"}, 2, CMD_INIT}
    };
    
    for (const auto& test_case : test_cases) {
        arguments_t local_args;
        memset(&local_args, 0, sizeof(local_args));
        
        char* argv[10];
        for (int i = 0; i < test_case.argc; i++) {
            argv[i] = (char*)test_case.argv[i];
        }
        
        EXPECT_EQ(parse_arguments(test_case.argc, argv, &local_args), 0);
        EXPECT_EQ(local_args.command, test_case.expected_command);
    }
}

TEST_F(ArgParseTest, ParseCommandsWithRequiredArgs) {
    struct TestCase {
        const char* argv[10];
        int argc;
        command_t expected_command;
    } test_cases[] = {
        {{"securekey", "store", "-s", "github", "-u", "user1"}, 6, CMD_STORE},
        {{"securekey", "add", "-s", "github", "-u", "user2"}, 6, CMD_STORE},
        {{"securekey", "get", "-s", "gmail", "-u", "user3"}, 6, CMD_RETRIEVE},
        {{"securekey", "retrieve", "-s", "amazon", "-u", "user4"}, 6, CMD_RETRIEVE},
        {{"securekey", "remove", "-s", "twitter", "-u", "user5"}, 6, CMD_REMOVE},
        {{"securekey", "rm", "-s", "facebook", "-u", "user6"}, 6, CMD_REMOVE},
        {{"securekey", "totp", "--secret", "JBSWY3DPEHPK3PXP"}, 4, CMD_TOTP},
        {{"securekey", "2fa", "--secret", "ABCDEFG123456"}, 4, CMD_TOTP},
        {{"securekey", "check", "-p", "MyPassword123!"}, 4, CMD_CHECK},
        {{"securekey", "validate", "-p", "AnotherPass456@"}, 4, CMD_CHECK}
    };
    
    for (const auto& test_case : test_cases) {
        arguments_t local_args;
        memset(&local_args, 0, sizeof(local_args));
        
        char* argv[10];
        for (int i = 0; i < test_case.argc; i++) {
            argv[i] = (char*)test_case.argv[i];
        }
        
        EXPECT_EQ(parse_arguments(test_case.argc, argv, &local_args), 0);
        EXPECT_EQ(local_args.command, test_case.expected_command);
        
        if (test_case.expected_command == CMD_STORE || 
            test_case.expected_command == CMD_RETRIEVE || 
            test_case.expected_command == CMD_REMOVE) {
            EXPECT_STRNE(local_args.service, "");
            EXPECT_STRNE(local_args.username, "");
        } else if (test_case.expected_command == CMD_TOTP) {
            EXPECT_STRNE(local_args.totp_secret, "");
        } else if (test_case.expected_command == CMD_CHECK) {
            EXPECT_STRNE(local_args.password, "");
        }
    }
}

TEST_F(ArgParseTest, ParseWithAllOptions) {
    const char* argv[] = {
        "securekey", "store", 
        "--service", "github", 
        "--username", "user@example.com",
        "--vault", "my_vault.dat",
        "--verbose"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    EXPECT_EQ(parse_arguments(argc, (char**)argv, &args), 0);
    EXPECT_EQ(args.command, CMD_STORE);
    EXPECT_STREQ(args.service, "github");
    EXPECT_STREQ(args.username, "user@example.com");
    EXPECT_STREQ(args.vault_file, "my_vault.dat");
    EXPECT_EQ(args.verbose, 1);
}

TEST_F(ArgParseTest, ParsePasswordCheck) {
    const char* argv[] = {
        "securekey", "check",
        "--password", "MySecurePass123!"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    EXPECT_EQ(parse_arguments(argc, (char**)argv, &args), 0);
    EXPECT_EQ(args.command, CMD_CHECK);
    EXPECT_STREQ(args.password, "MySecurePass123!");
}

TEST_F(ArgParseTest, ParsePasswordGenerate) {
    const char* argv[] = {
        "securekey", "generate",
        "--length", "20",
        "--show"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    EXPECT_EQ(parse_arguments(argc, (char**)argv, &args), 0);
    EXPECT_EQ(args.command, CMD_GENERATE);
    EXPECT_EQ(args.password_length, 20);
    EXPECT_EQ(args.show_password, 1);
}

TEST_F(ArgParseTest, InvalidPasswordLength) {
    const char* argv[] = {
        "securekey", "generate",
        "--length", "5"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    EXPECT_EQ(parse_arguments(argc, (char**)argv, &args), -1);
}

TEST_F(ArgParseTest, MissingRequiredArgs) {
    const char* test_cases[][4] = {
        {"securekey", "store", "--service", "github"},
        {"securekey", "get", "--username", "user"},
        {"securekey", "totp"},
        {"securekey", "check"}
    };
    
    for (int i = 0; i < 4; i++) {
        arguments_t local_args;
        memset(&local_args, 0, sizeof(local_args));
        
        int argc = (i == 2 || i == 3) ? 2 : 4;
        char* argv[4];
        for (int j = 0; j < argc; j++) {
            argv[j] = (char*)test_cases[i][j];
        }
        
        EXPECT_EQ(parse_arguments(argc, argv, &local_args), -1);
    }
}

TEST_F(ArgParseTest, HelpAndVersion) {
    const char* help_argv[] = {"securekey", "--help"};
    const char* version_argv[] = {"securekey", "--version"};
    
    testing::internal::CaptureStdout();
    EXPECT_EXIT(parse_arguments(2, (char**)help_argv, &args), 
                testing::ExitedWithCode(0), "");
    testing::internal::GetCapturedStdout();
    
    testing::internal::CaptureStdout();
    EXPECT_EXIT(parse_arguments(2, (char**)version_argv, &args), 
                testing::ExitedWithCode(0), "");
    testing::internal::GetCapturedStdout();
}

TEST_F(ArgParseTest, CommandToString) {
    EXPECT_STREQ(command_to_string(CMD_STORE), "store");
    EXPECT_STREQ(command_to_string(CMD_RETRIEVE), "get");
    EXPECT_STREQ(command_to_string(CMD_LIST), "list");
    EXPECT_STREQ(command_to_string(CMD_REMOVE), "remove");
    EXPECT_STREQ(command_to_string(CMD_TOTP), "totp");
    EXPECT_STREQ(command_to_string(CMD_CHECK), "check");
    EXPECT_STREQ(command_to_string(CMD_GENERATE), "generate");
    EXPECT_STREQ(command_to_string(CMD_INIT), "init");
    EXPECT_STREQ(command_to_string(CMD_NONE), "unknown");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
