# Project Structure

```
cybersecurity-solutions/
│
├── main.py                      # Main application with interactive menu
├── requirements.txt             # Python dependencies
├── README.md                    # Comprehensive documentation
├── QUICK_START.md              # Quick start guide
├── PROJECT_STRUCTURE.md        # This file
├── example_usage.py            # Example usage scripts
├── .gitignore                  # Git ignore file
│
├── password_security.py        # Password strength checking and generation
├── file_encryption.py          # File encryption/decryption (AES-256)
├── network_security.py         # Network scanning and security checks
├── security_utilities.py       # Hash generation, keys, tokens
└── data_privacy.py             # Data privacy and masking tools
```

## Module Descriptions

### Core Modules

1. **password_security.py**
   - Password strength analysis
   - Secure password generation
   - Password validation
   - Common password detection

2. **file_encryption.py**
   - AES-256 file encryption
   - String encryption/decryption
   - PBKDF2 key derivation
   - Secure file storage

3. **network_security.py**
   - Port scanning
   - SSL certificate checking
   - DNS security checks
   - Network connectivity testing
   - Local network information

4. **security_utilities.py**
   - Multiple hash algorithms (MD5, SHA1, SHA256, SHA512)
   - File hashing
   - API key generation
   - Secret token generation
   - Argon2 password hashing
   - CSRF token generation
   - File integrity verification

5. **data_privacy.py**
   - Sensitive data detection
   - Email/phone/SSN/credit card masking
   - Text sanitization
   - Pseudonym generation
   - Data anonymization

### Application Files

- **main.py**: Interactive command-line interface
- **example_usage.py**: Code examples for each module
- **requirements.txt**: Required Python packages
- **README.md**: Full documentation
- **QUICK_START.md**: Quick start guide

## Dependencies

- `cryptography`: Encryption and cryptographic operations
- `requests`: HTTP requests for network operations
- `python-nmap`: Network scanning (optional, for advanced scanning)
- `colorama`: Colored terminal output (Windows support)
- `argon2-cffi`: Argon2 password hashing

## Getting Started

1. Install dependencies: `pip install -r requirements.txt`
2. Run the application: `python main.py`
3. Or use individual modules: `python example_usage.py`

## Features Overview

✅ Password Security Tools
✅ File Encryption/Decryption
✅ Network Security Scanner
✅ Security Utilities (Hashes, Keys, Tokens)
✅ Data Privacy Tools
✅ Interactive Menu Interface
✅ Comprehensive Documentation
✅ Example Usage Scripts
