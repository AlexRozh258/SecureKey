CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -Iinclude -g
CXXFLAGS = -Wall -Wextra -Iinclude -g -std=c++14
LDFLAGS = -lssl -lcrypto
TEST_LDFLAGS = -lssl -lcrypto -lgtest -lgtest_main -pthread
TEST_GLOBAL_SOURCE = tests/test_global.cpp

C_SOURCES = src/crypto_engine.c src/vault_controller.c src/totp_engine.c src/arg_parse.c src/utilities.c
MAIN_SOURCE = src/main.c

TARGET = securekey
DEPS = include/arg_parse.h include/vault_controller.h include/crypto_engine.h include/totp_engine.h include/utilities.h

all: $(TARGET)

$(TARGET): $(MAIN_SOURCE) $(C_SOURCES) $(DEPS)
	$(CC) $(CFLAGS) $(MAIN_SOURCE) $(C_SOURCES) -o $(TARGET) $(LDFLAGS)

C_OBJECTS = $(C_SOURCES:.c=.o)

src/crypto_engine.o: src/crypto_engine.c $(DEPS)
	$(CC) $(CFLAGS) -c src/crypto_engine.c -o src/crypto_engine.o

src/vault_controller.o: src/vault_controller.c $(DEPS)
	$(CC) $(CFLAGS) -c src/vault_controller.c -o src/vault_controller.o

src/totp_engine.o: src/totp_engine.c $(DEPS)
	$(CC) $(CFLAGS) -c src/totp_engine.c -o src/totp_engine.o

src/arg_parse.o: src/arg_parse.c $(DEPS)
	$(CC) $(CFLAGS) -c src/arg_parse.c -o src/arg_parse.o

src/utilities.o: src/utilities.c $(DEPS)
	$(CC) $(CFLAGS) -c src/utilities.c -o src/utilities.o

clean:
	rm -f $(TARGET) test_crypto test_totp test_vault test_parser test_global *.o src/*.o tests/*.o

test: test_crypto test_totp test_vault test_parser test_global

valgrind_crypto: test_crypto
	@echo "Running Crypto Tests with Valgrind"
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./test_crypto

valgrind_totp: test_totp
	@echo "Running TOTP Tests with Valgrind"
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./test_totp

valgrind_vault: test_vault
	@echo "Running Vault Tests with Valgrind"
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./test_vault

valgrind_parser: test_parser
	@echo "Running Parser Tests with Valgrind"
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./test_parser

valgrind_global: test_global
	@echo "Running Global Tests with Valgrind"
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./test_global

valgrind_all: valgrind_crypto valgrind_totp valgrind_vault valgrind_parser valgrind_global
	@echo "All Valgrind tests completed successfully"

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
