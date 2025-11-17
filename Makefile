CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -Iinclude -g
CXXFLAGS = -Wall -Wextra -Iinclude -g -std=c++14
LDFLAGS = -lssl -lcrypto
TEST_LDFLAGS = -lssl -lcrypto -lgtest -lgtest_main -pthread
TEST_GLOBAL_SOURCE = tests/test_global.cpp

C_SOURCES = src/crypto_engine.c src/vault_controller.c src/totp_engine.c src/arg_parse.c
MAIN_SOURCE = src/main.c

TARGET = securekey
DEPS = include/arg_parse.h include/vault_controller.h include/crypto_engine.h include/totp_engine.h

all: $(TARGET)

$(TARGET): $(MAIN_SOURCE) $(C_SOURCES) $(DEPS)
	$(CC) $(CFLAGS) $(MAIN_SOURCE) $(C_SOURCES) -o $(TARGET) $(LDFLAGS)

C_OBJECTS = $(C_SOURCES:.c=.o)

src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) test_crypto test_totp test_vault test_parser test_global *.o src/*.o tests/*.o

test: test_crypto test_totp test_vault test_parser test_global

test_crypto: tests/test_crypto.cpp $(C_OBJECTS) $(DEPS)
	$(CXX) $(CXXFLAGS) tests/test_crypto.cpp $(C_OBJECTS) -o test_crypto $(TEST_LDFLAGS)
	@echo "Running Crypto Tests"
	./test_crypto

test_totp: tests/test_totp.cpp $(C_OBJECTS) $(DEPS)
	$(CXX) $(CXXFLAGS) tests/test_totp.cpp $(C_OBJECTS) -o test_totp $(TEST_LDFLAGS)
	@echo "Running TOTP Tests"
	./test_totp

test_vault: tests/test_vault.cpp $(C_OBJECTS) $(DEPS)
	$(CXX) $(CXXFLAGS) tests/test_vault.cpp $(C_OBJECTS) -o test_vault $(TEST_LDFLAGS)
	@echo "Running Vault Tests"
	./test_vault

test_parser: tests/test_parser.cpp $(C_OBJECTS) $(DEPS)
	$(CXX) $(CXXFLAGS) tests/test_parser.cpp $(C_OBJECTS) -o test_parser $(TEST_LDFLAGS)
	@echo "Running Parser Tests"
	./test_parser

test_global: $(TEST_GLOBAL_SOURCE) $(C_OBJECTS) $(DEPS)
	$(CXX) $(CXXFLAGS) $(TEST_GLOBAL_SOURCE) $(C_OBJECTS) -o test_global $(TEST_LDFLAGS)
	@echo "Running Global Tests"
	./test_global
