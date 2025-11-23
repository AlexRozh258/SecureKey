# SecureKey - Complete Documentation

**Authors**: Ioanna Havryliuk, Poremska Liudmyla, Oleksandr Rozheliuk

---

## Table of Contents

1. [Environment Setup](#1-environment-setup)
2. [User Instructions](#2-user-instructions)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Function Descriptions](#4-function-descriptions)
5. [Key Implementation Details](#5-key-implementation-details)

---

## 1. Environment Setup

### 1.1 System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian) or WSL2 on Windows
- **Compiler**: GCC 7.0+ and G++ 14+
- **Build System**: GNU Make 4.0+
- **Libraries**:
  - OpenSSL 1.1.1+ (libssl-dev, libcrypto)
  - Google Test (libgtest-dev) - for testing
- **Tools** (optional):
  - Valgrind - for memory leak detection
  - Git - for version control

**Note for Windows Users**:
This project requires a full Linux environment. You must install WSL2 (Windows Subsystem for Linux 2) with a complete Ubuntu distribution. Native Windows compilation is not supported. To set up WSL2:

1. Open PowerShell as Administrator and run:
   ```powershell
   wsl --install
   ```
2. Restart your computer
3. Install Ubuntu from Microsoft Store
4. Launch Ubuntu and follow the dependency installation instructions below

### 1.2 Installing Dependencies

#### Ubuntu/Debian (including WSL2):
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev libgtest-dev valgrind git
```

### 1.3 Verifying Installation

Check that all tools are installed correctly:

```bash
# Check GCC version
gcc --version
# Expected: gcc (Ubuntu) 9.4.0 or newer

# Check G++ version
g++ --version
# Expected: g++ (Ubuntu) 9.4.0 or newer

# Check OpenSSL
openssl version
# Expected: OpenSSL 1.1.1 or newer

# Check Make
make --version
# Expected: GNU Make 4.2 or newer
```

### 1.4 Building the Project

1. **Clone the repository** (if using Git):
```bash
git clone https://github.com/AlexRozh258/SecureKey.git
cd SecureKey
```

2. **Build the project**:
```bash
make clean  # Clean previous builds
make        # Compile SecureKey
```

Expected output:
```
gcc -Wall -Wextra -Iinclude -g src/main.c src/crypto_engine.c src/vault_controller.c src/totp_engine.c src/arg_parse.c src/utilities.c -o securekey -lssl -lcrypto
```

3. **Verify the build**:
```bash
./securekey --version
```

4. **Run tests**:
```bash
make test  # Run all unit tests
```

Expected: All 57 tests pass

5. **Check for memory leaks** (optional):
```bash
make valgrind_all
```

Expected: No memory leaks detected

### 1.5 Project Structure

```
SecureKey/
├── include/              # Header files
│   ├── arg_parse.h       # CLI argument parser
│   ├── crypto_engine.h   # Encryption/decryption
│   ├── totp_engine.h     # TOTP generation
│   ├── utilities.h       # Helper functions
│   └── vault_controller.h # Vault management
├── src/                  # Source files
│   ├── arg_parse.c
│   ├── crypto_engine.c
│   ├── main.c            # Main entry point
│   ├── totp_engine.c
│   ├── utilities.c
│   └── vault_controller.c
├── tests/                # Unit tests
│   ├── test_crypto.cpp
│   ├── test_global.cpp
│   ├── test_parser.cpp
│   ├── test_totp.cpp
│   └── test_vault.cpp
├── Makefile              # Build configuration
├── README.md             # Project overview
├── USAGE.md              # Detailed usage guide
├── QUICK_START.md        # Quick start guide
└── TOTP_SETUP_GUIDE.md   # 2FA setup instructions
```

---

## 2. User Instructions

### 2.1 First Time Setup

#### Step 1: Initialize Vault

Create a new encrypted vault with a master password:

```bash
./securekey init
```

You will be prompted:
```
Enter master password: ********
Confirm master password: ********
Vault created successfully at: ~/.securekey/vault.dat
```

**IMPORTANT**: Remember your master password! There is no recovery mechanism.

#### Step 2: Store Your First Password

```bash
./securekey store -s GitHub -u myusername@email.com
```

Prompts:
```
Enter master password: ********
Enter password to store: ********
Stored entry for 'GitHub' (myusername@email.com)
```

#### Step 3: Retrieve Password

```bash
./securekey get -s GitHub -u myusername@email.com --show
```

Output:
```
Enter master password: ********
Service: GitHub
Username: myusername@email.com
Password: your_stored_password
```

### 2.2 Common Operations

#### List All Stored Credentials

```bash
./securekey list
```

Output:
```
=== Vault Entries (3) ===

  1. GitHub          myusername@email.com
  2. Gmail           user@gmail.com
  3. AWS             admin                [TOTP]
```

#### Update Existing Entry

```bash
./securekey store -s GitHub -u myusername@email.com
# Will prompt to overwrite
```

#### Delete Entry

```bash
./securekey remove -s GitHub -u myusername@email.com
```

#### Generate Strong Password

```bash
./securekey generate --length 20 --show
```

Output:
```
Generated Password: Kx7$mP2@qL9#nR5&wT3!
```

#### Check Password Strength

```bash
./securekey check -p "MyPassword123!"
```

Output:
```
Password strength analysis:
  Length: 14 characters [GOOD]
  Lowercase letters: Yes
  Uppercase letters: Yes
  Digits: Yes
  Special characters: Yes

Overall strength: STRONG
```

### 2.3 Two-Factor Authentication (TOTP)

#### Store Credentials with TOTP

```bash
./securekey store -s Google -u myemail@gmail.com --secret JBSWY3DPEHPK3PXP
```

#### Retrieve with TOTP Code

```bash
./securekey get -s Google -u myemail@gmail.com
```

Output:
```
Service: Google
Username: myemail@gmail.com
Password: [hidden] (use --show to display)
TOTP Secret: JBSWY3DPEHPK3PXP
Current TOTP Code: 582941  ← Use this for 2FA login!
```

**Note**: TOTP codes change every 30 seconds.

#### Generate TOTP Code Only

```bash
./securekey totp --secret JBSWY3DPEHPK3PXP
```

Output:
```
TOTP Code: 582941
```

### 2.4 Advanced Features

#### Change Master Password

```bash
./securekey change-password
```

Prompts:
```
Enter current master password: ********
Enter new master password: ********
Confirm new master password: ********
Master password changed successfully
```

#### Use Custom Vault Location

```bash
./securekey init -v /path/to/my_vault.dat
./securekey store -v /path/to/my_vault.dat -s Service -u user
```

#### Backup and Restore

Backups are created automatically at `~/.securekey/vault.dat.backup` on every modification.

Manual backup:
```bash
cp ~/.securekey/vault.dat ~/my_backup_vault.dat
```

Restore:
```bash
cp ~/my_backup_vault.dat ~/.securekey/vault.dat
```

### 2.5 Command Reference

```bash
./securekey <command> [options]

Commands:
  init               Initialize new vault
  store, add         Store new password
  get, retrieve      Retrieve password
  list, ls           List all entries
  remove, rm         Remove entry
  totp, 2fa          Generate TOTP code
  generate, gen      Generate random password
  check, validate    Check password strength
  change-password    Change master password

Options:
  -s, --service <name>     Service name
  -u, --username <name>    Username/email
  -v, --vault <file>       Vault file path
      --secret <key>       TOTP Base32 secret
  -p, --password <pass>    Password to check
  -l, --length <num>       Password length (8-64)
      --show               Show password in plain text
      --verbose            Verbose output
  -h, --help               Show help
      --version            Show version
```

---

## 3. High-Level Architecture

### 3.1 System Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│                      SecureKey Application                         │
│                           (main.c)                                 │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                    ┌────────┴─────────┐
                    │                  │
         ┌──────────▼──────────┐  ┌───▼──────────────┐
         │   Argument Parser   │  │  User Interface  │
         │    (arg_parse.c)    │  │  (stdio/termios) │
         └──────────┬──────────┘  └───┬──────────────┘
                    │                 │
                    └────────┬────────┘
                             │
         ┌───────────────────▼────────────────────┐
         │      Application Logic Layer           │
         │  ┌─────────────────────────────────┐   │
         │  │   Vault Controller              │   │
         │  │   (vault_controller.c)          │   │
         │  │                                 │   │
         │  │  - Store credentials            │   │
         │  │  - Retrieve credentials         │   │
         │  │  - List entries                 │   │
         │  │  - Remove entries               │   │
         │  │  - Change master password       │   │
         │  │  - Backup/Restore               │   │
         │  └────────┬─────────────────┬──────┘   │
         └───────────┼─────────────────┼──────────┘
                     │                 │
        ┌────────────▼──────┐   ┌──────▼─────────────┐
        │  Crypto Engine    │   │   Utilities        │
        │ (crypto_engine.c) │   │  (utilities.c)     │
        │                   │   │                    │
        │ - AES-256-GCM     │   │ - Password gen     │
        │ - PBKDF2          │   │ - Strength check   │
        │ - Key derivation  │   │ - Secure input     │
        └────────┬──────────┘   └────────────────────┘
                 │
        ┌────────▼──────────┐
        │   TOTP Engine     │
        │  (totp_engine.c)  │
        │                   │
        │ - RFC 6238 TOTP   │
        │ - Base32 codec    │
        │ - HMAC-SHA1       │
        └────────┬──────────┘
                 │
        ┌────────▼──────────┐
        │  OpenSSL Library  │
        │                   │
        │ - EVP API         │
        │ - RAND_bytes      │
        │ - HMAC            │
        └────────┬──────────┘
                 │
        ┌────────▼──────────┐
        │   File System     │
        │                   │
        │ ~/.securekey/     │
        │   vault.dat       │
        │   vault.dat.bkp   │
        └───────────────────┘
```

### 3.2 Data Flow Diagram - Storing Password

```
   User
    │
    ├─> Command: ./securekey store -s GitHub -u user@email.com
    │
    ▼
┌──────────────────┐
│  arg_parse.c     │
│  Parse arguments │
└────────┬─────────┘
         │
         ├─> Validate: service="GitHub", username="user@email.com"
         │
    ▼
┌──────────────────┐
│  utilities.c     │
│  Read password   │
│  (no echo)       │
└────────┬─────────┘
         │
         ├─> Master password: "********"
         ├─> Password to store: "********"
         │
    ▼
┌────────────────────┐
│ vault_controller.c │
│ vault_init()       │
└────────┬───────────┘
         │
         ├─> Check if vault exists
         │   │
         │   ├─ YES → Load existing vault
         │   └─ NO  → Create new vault
         │
    ▼
┌────────────────────┐
│  crypto_engine.c   │
│  derive_key_with_  │
│  salt()            │
└────────┬───────────┘
         │
         ├─> PBKDF2(master_password, salt, 100k iter) → key
         │
    ▼
┌────────────────────┐
│  crypto_engine.c   │
│  decrypt_data()    │
└────────┬───────────┘
         │
         ├─> AES-256-GCM decrypt → existing entries
         │
    ▼
┌────────────────────┐
│ vault_controller.c │
│ vault_store()      │
└────────┬───────────┘
         │
         ├─> Add/update entry in memory
         │   {
         │     service: "GitHub",
         │     username: "user@email.com",
         │     password: "********",
         │     totp_secret: ""
         │   }
         │
    ▼
┌────────────────────┐
│  crypto_engine.c   │
│  encrypt_data()    │
└────────┬───────────┘
         │
         ├─> Generate random IV
         ├─> AES-256-GCM encrypt(entries, key, IV)
         ├─> Output: [IV | Ciphertext | Auth Tag]
         │
    ▼
┌────────────────────┐
│ vault_controller.c │
│ Write to file      │
└────────┬───────────┘
         │
         ├─> Write header (magic, version, salt, count)
         ├─> Write encrypted data
         ├─> Set permissions: chmod 0600
         ├─> Create backup: vault.dat.backup
         │
    ▼
   Success
```

### 3.3 Component Interaction - TOTP Generation

```
   User
    │
    ├─> Command: ./securekey get -s Google -u user@gmail.com
    │
    ▼
vault_get() → Retrieve entry with TOTP secret: "JBSWY3DPEHPK3PXP"
    │
    ▼
┌────────────────────┐
│  totp_engine.c     │
│  generate_totp()   │
└────────┬───────────┘
         │
         ├─> base32_decode("JBSWY3DPEHPK3PXP") → binary secret
         │
         ├─> Get current Unix time
         ├─> T = floor(time / 30)
         │
         ├─> HMAC-SHA1(secret, T) → hash (20 bytes)
         │
         ├─> Dynamic truncation:
         │     offset = hash[19] & 0x0F
         │     code = hash[offset..offset+3]
         │
         ├─> code = code & 0x7FFFFFFF
         ├─> code = code % 1,000,000
         │
    ▼
   Display TOTP Code: 582941
```

### 3.4 Security Architecture

```
┌─────────────────────────────────────────────────────┐
│              Security Layers                        │
├─────────────────────────────────────────────────────┤
│  Layer 1: User Authentication                       │
│  ┌───────────────────────────────────────────────┐  │
│  │ Master Password (never stored)                │  │
│  │   ↓ PBKDF2-HMAC-SHA256 (100,000 iterations)  │  │
│  │ 256-bit Encryption Key                        │  │
│  └───────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  Layer 2: Data Encryption                          │
│  ┌───────────────────────────────────────────────┐  │
│  │ AES-256-GCM (Authenticated Encryption)        │  │
│  │  - Encryption: Confidentiality                │  │
│  │  - Auth Tag: Integrity & Authenticity         │  │
│  │  - Random IV: Prevents pattern detection      │  │
│  └───────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  Layer 3: File System Security                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ File Permissions: 0600 (owner only)           │  │
│  │ Hidden directory: ~/.securekey/               │  │
│  │ Automatic backups: .backup extension          │  │
│  └───────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  Layer 4: Memory Security                          │
│  ┌───────────────────────────────────────────────┐  │
│  │ Secure memory wiping: OPENSSL_cleanse()       │  │
│  │ No password logging or debug output           │  │
│  │ Stack-allocated buffers where possible        │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 4. Function Descriptions

### 4.1 Crypto Engine (crypto_engine.c)

#### `int crypto_init(void)`
**Purpose**: Initializes OpenSSL library and loads algorithms.

**Returns**:
- `0` on success
- `-1` on failure

**Usage**: Call once at program startup before any crypto operations.

**Example**:
```c
if (crypto_init() != 0) {
    fprintf(stderr, "Failed to initialize crypto engine\n");
    return -1;
}
```

---

#### `int crypto_cleanup(void)`
**Purpose**: Cleans up OpenSSL resources and frees memory.

**Returns**: `0` on success

**Usage**: Call once at program shutdown.

**Example**:
```c
crypto_cleanup();
```

---

#### `int derive_key_with_salt(const char* password, const unsigned char* salt, size_t salt_len, unsigned char* key)`
**Purpose**: Derives a 256-bit encryption key from password using PBKDF2-HMAC-SHA256.

**Parameters**:
- `password`: Master password (null-terminated string)
- `salt`: Salt bytes (16 bytes recommended)
- `salt_len`: Length of salt
- `key`: Output buffer for derived key (must be 32 bytes)

**Returns**:
- `0` on success
- `-1` on failure

**Algorithm**: PBKDF2-HMAC-SHA256 with 100,000 iterations

**Example**:
```c
unsigned char salt[16];
unsigned char key[32];
RAND_bytes(salt, 16);

if (derive_key_with_salt("my_password", salt, 16, key) == 0) {
    // key now contains 256-bit encryption key
}
```

---

#### `int encrypt_data(const unsigned char* plaintext, size_t len, const unsigned char* key, unsigned char* ciphertext)`
**Purpose**: Encrypts data using AES-256-GCM.

**Parameters**:
- `plaintext`: Data to encrypt
- `len`: Length of plaintext
- `key`: 256-bit encryption key (32 bytes)
- `ciphertext`: Output buffer (must be len + IV_SIZE + TAG_SIZE)

**Returns**:
- `0` on success
- `-1` on failure

**Output Format**: `[IV (16 bytes) | Ciphertext | Auth Tag (16 bytes)]`

**Example**:
```c
unsigned char plaintext[] = "Secret data";
unsigned char ciphertext[sizeof(plaintext) + 32];
unsigned char key[32];

if (encrypt_data(plaintext, sizeof(plaintext), key, ciphertext) == 0) {
    // ciphertext contains encrypted data
}
```

---

#### `int decrypt_data(const unsigned char* ciphertext, size_t len, const unsigned char* key, unsigned char* plaintext)`
**Purpose**: Decrypts data encrypted with AES-256-GCM.

**Parameters**:
- `ciphertext`: Encrypted data (IV | ciphertext | tag)
- `len`: Total length of ciphertext
- `key`: 256-bit encryption key (32 bytes)
- `plaintext`: Output buffer for decrypted data

**Returns**:
- `0` on success (authentication verified)
- `-1` on failure (wrong key or tampered data)

**Example**:
```c
unsigned char ciphertext[512];
unsigned char plaintext[512];
unsigned char key[32];

if (decrypt_data(ciphertext, 512, key, plaintext) == 0) {
    // plaintext contains decrypted data
} else {
    // Wrong password or tampered data
}
```

---

#### `void secure_cleanup(void* data, size_t len)`
**Purpose**: Securely wipes memory to prevent sensitive data from lingering.

**Parameters**:
- `data`: Pointer to memory to wipe
- `len`: Number of bytes to wipe

**Usage**: Call on sensitive buffers (passwords, keys) before freeing.

**Example**:
```c
char password[256];
read_password_secure("Enter password: ", password, sizeof(password));
// ... use password ...
secure_cleanup(password, sizeof(password));
```

---

### 4.2 TOTP Engine (totp_engine.c)

#### `uint32_t generate_totp(const char* base32_secret)`
**Purpose**: Generates a 6-digit TOTP code (RFC 6238).

**Parameters**:
- `base32_secret`: TOTP secret in Base32 encoding (e.g., "JBSWY3DPEHPK3PXP")

**Returns**: 6-digit TOTP code (000000 - 999999)

**Algorithm**:
1. Decode Base32 secret to binary
2. Get current Unix time, divide by 30
3. HMAC-SHA1(secret, time_counter)
4. Dynamic truncation to get 31-bit value
5. Modulo 1,000,000 to get 6 digits

**Example**:
```c
uint32_t code = generate_totp("JBSWY3DPEHPK3PXP");
printf("TOTP Code: %06u\n", code);
// Output: TOTP Code: 582941
```

---

#### `int generate_totp_secret(char* output, size_t output_len)`
**Purpose**: Generates a random TOTP secret in Base32 encoding.

**Parameters**:
- `output`: Output buffer for Base32 string
- `output_len`: Size of output buffer (minimum 17 bytes)

**Returns**:
- `0` on success
- `-1` on failure

**Example**:
```c
char secret[32];
if (generate_totp_secret(secret, sizeof(secret)) == 0) {
    printf("New TOTP Secret: %s\n", secret);
    // Output: New TOTP Secret: 65ZTE3BBBY2XQ3DS
}
```

---

#### `int validate_totp(const char* base32_secret, uint32_t code)`
**Purpose**: Validates a TOTP code with time window tolerance.

**Parameters**:
- `base32_secret`: TOTP secret
- `code`: Code to validate

**Returns**:
- `1` if code is valid (within ±1 time window)
- `0` if code is invalid

**Time Tolerance**: Accepts codes from previous, current, and next 30-second windows (90s total).

**Example**:
```c
if (validate_totp("JBSWY3DPEHPK3PXP", 582941) == 1) {
    printf("Code is valid!\n");
} else {
    printf("Code is invalid\n");
}
```

---

### 4.3 Vault Controller (vault_controller.c)

#### `int vault_init(const char* master_password, const char* vault_path)`
**Purpose**: Initializes or opens an encrypted vault.

**Parameters**:
- `master_password`: Master password for vault
- `vault_path`: Path to vault file (NULL for default ~/.securekey/vault.dat)

**Returns**:
- `0` on success
- `-1` on failure

**Behavior**:
- If vault exists: Loads and decrypts entries
- If vault doesn't exist: Creates new vault with random salt

**Example**:
```c
if (vault_init("my_master_password", NULL) == 0) {
    // Vault is now open and ready
}
```

---

#### `int vault_store(const char* service, const char* username, const char* password, const char* totp_secret, bool force)`
**Purpose**: Stores or updates a credential entry.

**Parameters**:
- `service`: Service name (e.g., "GitHub")
- `username`: Username or email
- `password`: Password to store
- `totp_secret`: TOTP Base32 secret (NULL if none)
- `force`: If true, overwrites existing entry without prompting

**Returns**:
- `0` on success
- `-1` on failure

**Example**:
```c
vault_store("GitHub", "user@email.com", "password123", NULL, false);
vault_store("Google", "user@gmail.com", "pass456", "JBSWY3DPEHPK3PXP", false);
```

---

#### `int vault_get(const char* service, const char* username, VaultEntry* entry)`
**Purpose**: Retrieves a credential entry from vault.

**Parameters**:
- `service`: Service name
- `username`: Username
- `entry`: Output structure to store retrieved entry

**Returns**:
- `0` on success
- `-1` if entry not found

**Example**:
```c
VaultEntry entry;
if (vault_get("GitHub", "user@email.com", &entry) == 0) {
    printf("Password: %s\n", entry.password);
    if (strlen(entry.totp_secret) > 0) {
        uint32_t code = generate_totp(entry.totp_secret);
        printf("TOTP Code: %06u\n", code);
    }
}
```

---

#### `int vault_list(void)`
**Purpose**: Lists all entries in the vault.

**Returns**:
- `0` on success
- `-1` on failure

**Output Format**:
```
=== Vault Entries (3) ===

  1. GitHub          user@email.com
  2. Google          user@gmail.com    [TOTP]
  3. AWS             admin             [TOTP]
```

**Example**:
```c
vault_list();
```

---

#### `int vault_remove(const char* service, const char* username)`
**Purpose**: Removes an entry from the vault.

**Parameters**:
- `service`: Service name
- `username`: Username

**Returns**:
- `0` on success
- `-1` if entry not found

**Example**:
```c
vault_remove("GitHub", "user@email.com");
```

---

#### `int vault_change_master_password(const char* old_password, const char* new_password)`
**Purpose**: Changes the master password of the vault.

**Parameters**:
- `old_password`: Current master password
- `new_password`: New master password

**Returns**:
- `0` on success
- `-1` on failure (wrong old password)

**Process**:
1. Verify old password
2. Decrypt all entries with old key
3. Generate new salt
4. Derive new key from new password
5. Re-encrypt all entries
6. Save to file

**Example**:
```c
if (vault_change_master_password("old_pass", "new_pass") == 0) {
    printf("Password changed successfully\n");
}
```

---

#### `void vault_cleanup(void)`
**Purpose**: Closes vault and securely wipes all sensitive data from memory.

**Usage**: Call when done with vault operations.

**Example**:
```c
vault_cleanup();
```

---

### 4.4 Utilities (utilities.c)

#### `int check_password_strength(const char* password)`
**Purpose**: Analyzes password strength.

**Parameters**:
- `password`: Password to check

**Returns**:
- `0`: Very Weak (< 8 characters)
- `1`: Weak (8+ chars, 1 char class)
- `2`: Moderate (8+ chars, 2-3 char classes)
- `3`: Strong (12+ chars, 3+ char classes)
- `4`: Very Strong (16+ chars, 4 char classes)

**Character Classes**:
- Lowercase (a-z)
- Uppercase (A-Z)
- Digits (0-9)
- Special (!@#$%^&*()_+-=[]{}|;:,.<>?)

**Example**:
```c
int strength = check_password_strength("MyP@ssw0rd!");
switch (strength) {
    case 0: printf("Very Weak\n"); break;
    case 1: printf("Weak\n"); break;
    case 2: printf("Moderate\n"); break;
    case 3: printf("Strong\n"); break;
    case 4: printf("Very Strong\n"); break;
}
```

---

#### `int generate_random_password(char* output, size_t output_len, int length)`
**Purpose**: Generates a cryptographically secure random password.

**Parameters**:
- `output`: Output buffer
- `output_len`: Size of output buffer
- `length`: Desired password length (8-64)

**Returns**:
- `0` on success
- `-1` on failure

**Character Set**: A-Z, a-z, 0-9, !@#$%^&*()

**Example**:
```c
char password[65];
if (generate_random_password(password, sizeof(password), 16) == 0) {
    printf("Generated: %s\n", password);
    // Output: Generated: Kx7$mP2@qL9#nR5!
}
```

---

#### `int read_password_secure(const char* prompt, char* password, size_t max_len)`
**Purpose**: Reads password from terminal without echoing characters.

**Parameters**:
- `prompt`: Prompt to display
- `password`: Output buffer
- `max_len`: Maximum password length

**Returns**:
- `0` on success
- `-1` on failure

**Behavior**: Disables terminal echo, reads input, restores echo.

**Example**:
```c
char password[256];
read_password_secure("Enter master password: ", password, sizeof(password));
// User types password (not visible on screen)
```

---

### 4.5 Argument Parser (arg_parse.c)

#### `int parse_arguments(int argc, char *argv[], arguments_t *args)`
**Purpose**: Parses command-line arguments.

**Parameters**:
- `argc`: Argument count
- `argv`: Argument vector
- `args`: Output structure for parsed arguments

**Returns**:
- `0` on success
- `-1` on error

**Example**:
```c
arguments_t args;
if (parse_arguments(argc, argv, &args) == 0) {
    switch (args.command) {
        case CMD_STORE:
            // Handle store command
            break;
        case CMD_RETRIEVE:
            // Handle get command
            break;
        // ...
    }
}
```

---

#### `void print_usage(const char *program_name)`
**Purpose**: Prints usage information.

**Example**:
```c
print_usage(argv[0]);
```

---

#### `void print_version(void)`
**Purpose**: Prints version information.

**Example**:
```c
print_version();
```

---

## 5. Key Implementation Details

### 5.1 Encryption Scheme

**Algorithm**: AES-256-GCM (Galois/Counter Mode)

**Why AES-256-GCM?**
- **Authenticated Encryption**: Provides both confidentiality and authenticity
- **AEAD**: Detects tampering automatically
- **Performance**: Hardware-accelerated on modern CPUs
- **Standard**: NIST approved, industry standard

**Encryption Flow**:
```c
// Pseudocode
plaintext_data = {entry1, entry2, entry3, ...}
random_iv = generate_random_bytes(16)
key = derive_key_with_salt(master_password, vault_salt)

ciphertext, auth_tag = AES_256_GCM_encrypt(
    plaintext: plaintext_data,
    key: key,
    iv: random_iv
)

vault_file = {
    header: {magic, version, salt, entry_count},
    encrypted: {random_iv, ciphertext, auth_tag}
}
```

**Decryption Flow**:
```c
// Pseudocode
vault_file = read_from_disk()
header = parse_header(vault_file)
salt = header.salt

key = derive_key_with_salt(master_password, salt)

iv, ciphertext, auth_tag = parse_encrypted_section(vault_file)

plaintext_data = AES_256_GCM_decrypt(
    ciphertext: ciphertext,
    key: key,
    iv: iv,
    auth_tag: auth_tag
)

if (auth_tag_verification_failed) {
    // Wrong password OR tampered data
    return ERROR_DECRYPTION_FAILED
}

entries = deserialize(plaintext_data)
```

---

### 5.2 Key Derivation

**Algorithm**: PBKDF2-HMAC-SHA256

**Parameters**:
- **Iterations**: 100,000
- **Salt Size**: 16 bytes (128 bits)
- **Output Key**: 32 bytes (256 bits)

**Why PBKDF2?**
- **Slows down brute-force attacks**: 100k iterations makes each password attempt ~100ms
- **Salt prevents rainbow tables**: Each vault has unique salt
- **NIST approved**: SP 800-132 recommendation

**Implementation**:
```c
int derive_key_with_salt(const char* password,
                         const unsigned char* salt,
                         size_t salt_len,
                         unsigned char* key) {
    return PKCS5_PBKDF2_HMAC(
        password,           // Password string
        strlen(password),   // Password length
        salt,               // Salt bytes
        salt_len,           // Salt length (16)
        100000,             // Iterations
        EVP_sha256(),       // Hash function
        KEY_LEN,            // Output length (32)
        key                 // Output buffer
    );
}
```

**Unique Per Vault**:
- Each vault has a random 16-byte salt generated at creation
- Same password + different salt = different encryption key
- Salt is stored in plaintext in vault header (not secret)

---

### 5.3 TOTP Algorithm (RFC 6238)

**Standard**: Time-Based One-Time Password Algorithm

**Process**:

```
Step 1: Decode Base32 secret
    "JBSWY3DPEHPK3PXP" → binary_secret (10 bytes)

Step 2: Calculate time counter
    current_unix_time = time(NULL)
    T = current_unix_time / 30

    Example:
    time = 1700000000
    T = 1700000000 / 30 = 56666666

Step 3: HMAC-SHA1
    counter_bytes = T as 8-byte big-endian
    hash = HMAC-SHA1(binary_secret, counter_bytes)
    hash = 20 bytes

Step 4: Dynamic Truncation
    offset = hash[19] & 0x0F  // Last 4 bits (0-15)
    truncated = (hash[offset] << 24) |
                (hash[offset+1] << 16) |
                (hash[offset+2] << 8) |
                (hash[offset+3])

Step 5: Generate Code
    code = truncated & 0x7FFFFFFF  // Clear highest bit
    code = code % 1,000,000         // 6 digits

    Example: 582941
```

**Implementation**:
```c
uint32_t generate_totp(const char* base32_secret) {
    unsigned char secret[64];
    int secret_len = base32_decode(base32_secret, secret, sizeof(secret));

    time_t now = time(NULL);
    uint64_t T = now / 30;

    // Convert T to big-endian bytes
    unsigned char counter[8];
    for (int i = 7; i >= 0; i--) {
        counter[i] = T & 0xFF;
        T >>= 8;
    }

    // HMAC-SHA1
    unsigned char hash[20];
    HMAC(EVP_sha1(), secret, secret_len, counter, 8, hash, NULL);

    // Dynamic truncation
    int offset = hash[19] & 0x0F;
    uint32_t code = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset+1] & 0xFF) << 16) |
                    ((hash[offset+2] & 0xFF) << 8) |
                    (hash[offset+3] & 0xFF);

    return code % 1000000;
}
```

**Time Windows**:
- Current window: [now-30s, now]
- Validation accepts: previous, current, next window (±30s tolerance)
- Total validation window: 90 seconds

---

### 5.4 Vault File Format

The vault file is a binary file stored at `~/.securekey/vault.dat` with the following structure:

**Header Section** (28 bytes, unencrypted):
- **Magic Number**: 4-byte identifier "SKEY" to verify file format
- **Version**: 4-byte integer indicating format version (currently 1)
- **Salt**: 16-byte random value used for key derivation
- **Entry Count**: 4-byte integer showing how many credentials are stored

**Encrypted Section**:
- **Initialization Vector (IV)**: 16-byte random value for AES-GCM encryption
- **Ciphertext**: Encrypted credential data
- **Authentication Tag**: 16-byte tag to verify data integrity

**What's Stored in Each Entry**:
Each credential entry contains:
- Service name (e.g., "GitHub") - up to 256 characters
- Username or email - up to 256 characters
- Password - up to 256 characters
- TOTP secret (optional) - up to 64 characters

All entry data is encrypted using AES-256-GCM before being written to the file.

**File Size**:
- Empty vault: ~60 bytes
- With 1 entry: ~892 bytes
- Each additional entry adds ~832 bytes

**Security Features**:
- Only the header is readable without the master password
- All sensitive data (passwords, usernames, services) is encrypted
- Authentication tag prevents tampering
- File permissions are set to 0600 (owner read/write only)

---

### 5.5 Memory Security

**Sensitive Data Handling**:

1. **Secure Wiping**:
```c
void secure_cleanup(void* data, size_t len) {
    OPENSSL_cleanse(data, len);  // Prevents compiler optimization
}
```

2. **Password Buffers**:
```c
char master_password[256];
read_password_secure("Enter password: ", master_password, 256);
// ... use password ...
secure_cleanup(master_password, sizeof(master_password));
```

3. **Key Material**:
```c
typedef struct {
    unsigned char key[32];  // Encryption key
    VaultEntry* entries;    // Decrypted entries
    bool is_open;
} VaultState;

void vault_cleanup(void) {
    if (g_vault.is_open) {
        secure_cleanup(g_vault.key, sizeof(g_vault.key));
        if (g_vault.entries) {
            secure_cleanup(g_vault.entries,
                         g_vault.header.entry_count * sizeof(VaultEntry));
            free(g_vault.entries);
        }
        g_vault.is_open = false;
    }
}
```

4. **No Logging**:
- Passwords never printed to stdout/stderr
- No debug output containing sensitive data
- Error messages don't reveal sensitive information

---

### 5.6 File System Operations

**Atomic Writes**:
```c
// Write to temporary file first
char temp_path[512];
snprintf(temp_path, sizeof(temp_path), "%s.tmp", vault_path);

FILE* fp = fopen(temp_path, "wb");
fwrite(&header, sizeof(header), 1, fp);
fwrite(encrypted_data, encrypted_len, 1, fp);
fflush(fp);
fsync(fileno(fp));  // Ensure data is on disk
fclose(fp);

// Atomic rename (POSIX guarantee)
rename(temp_path, vault_path);
```

**File Permissions**:
```c
// Set owner-only read/write
chmod(vault_path, 0600);
```

**Automatic Backups**:
```c
int vault_backup(const char* vault_path) {
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.backup", vault_path);

    // Copy vault to backup
    FILE* src = fopen(vault_path, "rb");
    FILE* dst = fopen(backup_path, "wb");

    // Copy data
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }

    fclose(src);
    fclose(dst);

    // Set same permissions
    chmod(backup_path, 0600);

    return 0;
}
```

---

### 5.7 Error Handling Strategy

**Function Return Values**:
- `0` = Success
- `-1` = Error (check errno or OpenSSL error queue)
- Boolean functions: `true`/`false`

**Error Reporting**:
```c
if (vault_init(password, path) != 0) {
    fprintf(stderr, "Error: Failed to open vault\n");
    if (errno == ENOENT) {
        fprintf(stderr, "Vault does not exist. Run 'init' first.\n");
    } else {
        fprintf(stderr, "Wrong password or corrupted vault\n");
    }
    return -1;
}
```

**OpenSSL Error Handling**:
```c
if (PKCS5_PBKDF2_HMAC(...) != 1) {
    ERR_print_errors_fp(stderr);
    return -1;
}
```

---

### 5.8 Testing Strategy

**Test Coverage**:

1. **Unit Tests** (57 total):
   - Crypto: 5 tests (key derivation, encryption, decryption, wrong key, cleanup)
   - TOTP: 4 tests (generation, validation, Base32 encoding/decoding)
   - Vault: 21 tests (CRUD, persistence, backup, password change, security)
   - Parser: 9 tests (argument parsing, validation)
   - Integration: 18 tests (end-to-end workflows)

2. **Memory Tests** (Valgrind):
   - Zero memory leaks
   - No invalid memory access
   - No uninitialized values

**Running Tests**:
```bash
make test            # All tests
make valgrind_all    # Memory leak detection
```

**Test Example**:
```cpp
TEST(VaultTest, StoreAndGetEntry) {
    // Create vault
    ASSERT_EQ(vault_init("test_password", "/tmp/test_vault.dat"), 0);

    // Store entry
    ASSERT_EQ(vault_store("GitHub", "user@email.com", "pass123", NULL, false), 0);

    // Retrieve entry
    VaultEntry entry;
    ASSERT_EQ(vault_get("GitHub", "user@email.com", &entry), 0);
    EXPECT_STREQ(entry.password, "pass123");

    vault_cleanup();
    remove("/tmp/test_vault.dat");
}
```

---

## Summary

**SecureKey** is a robust command-line password manager that prioritizes security and simplicity. Built in C with industry-standard cryptography, it provides secure password storage, two-factor authentication support, and password generation capabilities.

**Key Strengths**:
- Strong encryption (AES-256-GCM) with authenticated encryption
- Secure key derivation (PBKDF2 with 100,000 iterations)
- TOTP support for two-factor authentication (RFC 6238 compliant)
- Memory-safe implementation with secure cleanup
- Comprehensive test coverage (57 tests, Valgrind verified)
- Simple command-line interface
- Automatic backup functionality

**Best For**:
- Users who prefer command-line tools
- Developers who want a simple, auditable password manager
- Anyone needing secure password storage with TOTP support
- Learning about cryptographic implementations in C

---
