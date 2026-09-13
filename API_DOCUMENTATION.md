# API Documentation

Complete API documentation for all cybersecurity toolkit modules.

## Table of Contents

1. [Password Security](#password-security)
2. [File Encryption](#file-encryption)
3. [Network Security](#network-security)
4. [Security Utilities](#security-utilities)
5. [Data Privacy](#data-privacy)
6. [Two-Factor Authentication](#two-factor-authentication)
7. [Secure Deletion](#secure-deletion)
8. [URL Security](#url-security)
9. [Email Security](#email-security)
10. [Security Headers](#security-headers)
11. [Security Audit](#security-audit)
12. [Certificate Analyzer](#certificate-analyzer)
13. [Backup Verification](#backup-verification)
14. [Config Security](#config-security)

---

## Password Security

**Module:** `password_security.py`

### PasswordSecurity Class

#### Methods

##### `check_strength(password: str) -> Tuple[int, str, List[str]]`
Check password strength and return score, feedback, and suggestions.

**Parameters:**
- `password` (str): Password to check

**Returns:**
- Tuple of (score 0-100, strength level, list of suggestions)

**Example:**
```python
from password_security import PasswordSecurity
ps = PasswordSecurity()
score, strength, feedback = ps.check_strength("MyPassword123!")
```

##### `generate_password(length: int = 16, ...) -> str`
Generate a secure random password.

**Parameters:**
- `length` (int): Password length (default: 16)
- `include_upper` (bool): Include uppercase letters (default: True)
- `include_lower` (bool): Include lowercase letters (default: True)
- `include_digits` (bool): Include digits (default: True)
- `include_special` (bool): Include special characters (default: True)

**Returns:**
- Generated password string

**Example:**
```python
password = ps.generate_password(length=20)
```

##### `validate_password(password: str, min_length: int = 8) -> bool`
Validate if password meets minimum requirements.

**Parameters:**
- `password` (str): Password to validate
- `min_length` (int): Minimum length (default: 8)

**Returns:**
- True if password meets requirements

---

## File Encryption

**Module:** `file_encryption.py`

### FileEncryption Class

#### Methods

##### `encrypt_file(input_file: str, output_file: str, password: str) -> bool`
Encrypt a file using AES-256.

**Parameters:**
- `input_file` (str): Path to file to encrypt
- `output_file` (str): Path for encrypted output file
- `password` (str): Encryption password

**Returns:**
- True if successful

**Example:**
```python
from file_encryption import FileEncryption
fe = FileEncryption()
fe.encrypt_file("data.txt", "data.enc", "my_password")
```

##### `decrypt_file(input_file: str, output_file: str, password: str) -> bool`
Decrypt a file using AES-256.

**Parameters:**
- `input_file` (str): Path to encrypted file
- `output_file` (str): Path for decrypted output file
- `password` (str): Decryption password

**Returns:**
- True if successful

##### `encrypt_string(plaintext: str, password: str) -> str`
Encrypt a string and return base64 encoded result.

**Parameters:**
- `plaintext` (str): Text to encrypt
- `password` (str): Encryption password

**Returns:**
- Base64 encoded encrypted string

##### `decrypt_string(encrypted_data: str, password: str) -> str`
Decrypt a base64 encoded string.

**Parameters:**
- `encrypted_data` (str): Base64 encoded encrypted data
- `password` (str): Decryption password

**Returns:**
- Decrypted string

---

## Network Security

**Module:** `network_security.py`

### NetworkSecurity Class

#### Methods

##### `check_port(host: str, port: int) -> Tuple[bool, str]`
Check if a port is open on a host.

**Parameters:**
- `host` (str): Hostname or IP address
- `port` (int): Port number to check

**Returns:**
- Tuple of (is_open, status_message)

##### `scan_common_ports(host: str, ports: List[int] = None) -> Dict[int, Tuple[bool, str]]`
Scan common ports on a host.

**Parameters:**
- `host` (str): Hostname or IP address
- `ports` (List[int]): List of ports to scan (defaults to common ports)

**Returns:**
- Dictionary mapping port numbers to (is_open, status) tuples

##### `check_website_ssl(url: str) -> Dict[str, any]`
Check SSL certificate information for a website.

**Parameters:**
- `url` (str): Website URL to check

**Returns:**
- Dictionary with SSL information

---

## Security Utilities

**Module:** `security_utilities.py`

### SecurityUtilities Class

#### Methods

##### `hash_string(text: str, algorithm: str = 'sha256') -> str`
Hash a string using specified algorithm.

**Parameters:**
- `text` (str): String to hash
- `algorithm` (str): Hash algorithm (md5/sha1/sha256/sha512)

**Returns:**
- Hexadecimal hash string

##### `hash_file(file_path: str, algorithm: str = 'sha256') -> Optional[str]`
Hash a file using specified algorithm.

**Parameters:**
- `file_path` (str): Path to file
- `algorithm` (str): Hash algorithm

**Returns:**
- Hexadecimal hash string or None

##### `generate_api_key(length: int = 32) -> str`
Generate a secure API key.

**Parameters:**
- `length` (int): Key length in bytes (default: 32)

**Returns:**
- Base64 encoded API key

##### `hash_password_argon2(password: str) -> str`
Hash password using Argon2.

**Parameters:**
- `password` (str): Password to hash

**Returns:**
- Argon2 hash string

##### `verify_password_argon2(password: str, hash_string: str) -> bool`
Verify password against Argon2 hash.

**Parameters:**
- `password` (str): Password to verify
- `hash_string` (str): Argon2 hash string

**Returns:**
- True if password matches

---

## Data Privacy

**Module:** `data_privacy.py`

### DataPrivacy Class

#### Methods

##### `detect_sensitive_data(text: str) -> Dict[str, List[str]]`
Detect sensitive data patterns in text.

**Parameters:**
- `text` (str): Text to analyze

**Returns:**
- Dictionary mapping data types to lists of detected values

##### `mask_email(email: str) -> str`
Mask email address for privacy.

**Parameters:**
- `email` (str): Email address to mask

**Returns:**
- Masked email string

##### `sanitize_text(text: str, mask_all: bool = False) -> str`
Sanitize text by masking sensitive data.

**Parameters:**
- `text` (str): Text to sanitize
- `mask_all` (bool): If True, mask all detected sensitive data

**Returns:**
- Sanitized text

---

## Two-Factor Authentication

**Module:** `two_factor_auth.py`

### TwoFactorAuth Class

#### Methods

##### `generate_secret_key(length: int = 32) -> str`
Generate a base32-encoded secret key for TOTP.

**Parameters:**
- `length` (int): Length of the secret key in bytes (default: 32)

**Returns:**
- Base32-encoded secret key

##### `generate_totp(secret_key: str, time_step: int = None, digits: int = None) -> str`
Generate TOTP code from secret key.

**Parameters:**
- `secret_key` (str): Base32-encoded secret key
- `time_step` (int): Time step in seconds (default: 30)
- `digits` (int): Number of digits in code (default: 6)

**Returns:**
- TOTP code as string

##### `verify_totp(secret_key: str, code: str, window: int = 1) -> bool`
Verify TOTP code.

**Parameters:**
- `secret_key` (str): Base32-encoded secret key
- `code` (str): TOTP code to verify
- `window` (int): Time window (default: 1)

**Returns:**
- True if code is valid

---

## Secure Deletion

**Module:** `secure_deletion.py`

### SecureDeletion Class

#### Methods

##### `shred_file(file_path: str, passes: int = None, verbose: bool = False) -> bool`
Securely delete a file by overwriting it multiple times.

**Parameters:**
- `file_path` (str): Path to file to delete
- `passes` (int): Number of overwrite passes (default: 3)
- `verbose` (bool): Print progress messages

**Returns:**
- True if successful

##### `shred_file_gutmann(file_path: str, verbose: bool = False) -> bool`
Securely delete file using Gutmann method (35 passes).

**Parameters:**
- `file_path` (str): Path to file to delete
- `verbose` (bool): Print progress messages

**Returns:**
- True if successful

---

## URL Security

**Module:** `url_security.py`

### URLSecurity Class

#### Methods

##### `analyze_url(url: str) -> Dict[str, any]`
Comprehensive URL security analysis.

**Parameters:**
- `url` (str): URL to analyze

**Returns:**
- Dictionary with analysis results

##### `check_url_reputation(url: str) -> Dict[str, any]`
Check URL reputation.

**Parameters:**
- `url` (str): URL to check

**Returns:**
- Dictionary with reputation information

##### `expand_short_url(url: str) -> Optional[str]`
Expand a shortened URL to see final destination.

**Parameters:**
- `url` (str): Shortened URL

**Returns:**
- Final URL or None

---

## Email Security

**Module:** `email_security.py`

### EmailSecurity Class

#### Methods

##### `analyze_email_headers(email_content: str) -> Dict[str, any]`
Analyze email headers for security information.

**Parameters:**
- `email_content` (str): Raw email content (headers + body)

**Returns:**
- Dictionary with header analysis

##### `analyze_email_content(email_body: str) -> Dict[str, any]`
Analyze email body for phishing indicators.

**Parameters:**
- `email_body` (str): Email body text

**Returns:**
- Dictionary with content analysis

##### `analyze_full_email(email_content: str) -> Dict[str, any]`
Comprehensive email analysis (headers + content).

**Parameters:**
- `email_content` (str): Full email content

**Returns:**
- Dictionary with complete analysis

---

## Security Headers

**Module:** `security_headers.py`

### SecurityHeaders Class

#### Methods

##### `check_security_headers(url: str) -> Dict[str, any]`
Check security headers for a website.

**Parameters:**
- `url` (str): Website URL to check

**Returns:**
- Dictionary with security headers analysis

##### `generate_security_report(url: str) -> str`
Generate a human-readable security report.

**Parameters:**
- `url` (str): URL to analyze

**Returns:**
- Formatted security report string

---

## Security Audit

**Module:** `security_audit.py`

### SecurityAudit Class

#### Methods

##### `analyze_log_file(log_file: str, pattern_type: str = 'all') -> Dict[str, any]`
Analyze log file for security events.

**Parameters:**
- `log_file` (str): Path to log file
- `pattern_type` (str): Type of patterns to check

**Returns:**
- Dictionary with analysis results

##### `detect_brute_force(log_file: str, threshold: int = 10) -> Dict[str, any]`
Detect brute force attack patterns in logs.

**Parameters:**
- `log_file` (str): Path to log file
- `threshold` (int): Number of failed attempts to consider as brute force

**Returns:**
- Dictionary with brute force detection results

##### `analyze_access_logs(log_file: str) -> Dict[str, any]`
Analyze web access logs for security issues.

**Parameters:**
- `log_file` (str): Path to access log file

**Returns:**
- Dictionary with access log analysis

---

## Certificate Analyzer

**Module:** `certificate_analyzer.py`

### CertificateAnalyzer Class

#### Methods

##### `analyze_certificate(hostname: str, port: int = 443) -> Dict[str, any]`
Analyze SSL/TLS certificate for a hostname.

**Parameters:**
- `hostname` (str): Hostname or IP address
- `port` (int): Port number (default: 443)

**Returns:**
- Dictionary with certificate information

##### `get_certificate_expiry_date(hostname: str, port: int = 443) -> Optional[datetime]`
Get certificate expiry date.

**Parameters:**
- `hostname` (str): Hostname to check
- `port` (int): Port number

**Returns:**
- Expiry date as datetime object or None

##### `generate_certificate_report(hostname: str, port: int = 443) -> str`
Generate human-readable certificate report.

**Parameters:**
- `hostname` (str): Hostname to analyze
- `port` (int): Port number

**Returns:**
- Formatted certificate report

---

## Backup Verification

**Module:** `backup_verification.py`

### BackupVerification Class

#### Methods

##### `verify_backup_integrity(backup_file: str, original_hash: str = None, algorithm: str = 'sha256') -> Dict[str, any]`
Verify backup file integrity.

**Parameters:**
- `backup_file` (str): Path to backup file
- `original_hash` (str): Expected hash value (optional)
- `algorithm` (str): Hash algorithm to use

**Returns:**
- Dictionary with verification results

##### `create_backup_manifest(directory: str, output_file: str = None, algorithm: str = 'sha256') -> Dict[str, any]`
Create a manifest file for directory backup.

**Parameters:**
- `directory` (str): Directory to create manifest for
- `output_file` (str): Path to save manifest file (optional)
- `algorithm` (str): Hash algorithm to use

**Returns:**
- Dictionary with manifest information

##### `verify_backup_against_manifest(directory: str, manifest_file: str) -> Dict[str, any]`
Verify backup directory against manifest.

**Parameters:**
- `directory` (str): Directory to verify
- `manifest_file` (str): Path to manifest file

**Returns:**
- Dictionary with verification results

---

## Config Security

**Module:** `config_security.py`

### ConfigSecurity Class

#### Methods

##### `check_file_permissions(file_path: str) -> Dict[str, any]`
Check file permissions for security.

**Parameters:**
- `file_path` (str): Path to file

**Returns:**
- Dictionary with permission information

##### `check_environment_variables() -> Dict[str, any]`
Check environment variables for sensitive data.

**Returns:**
- Dictionary with environment variable analysis

##### `check_ssh_config(config_file: str = None) -> Dict[str, any]`
Check SSH configuration security (Linux/Mac).

**Parameters:**
- `config_file` (str): Path to SSH config file (default: ~/.ssh/config)

**Returns:**
- Dictionary with SSH config analysis

---

## Common Patterns

### Error Handling

All modules return dictionaries with error fields when exceptions occur:
```python
result = module.method()
if 'error' in result:
    print(f"Error: {result['error']}")
```

### Security Scores

Many modules return security scores (0-100):
- 80-100: Good/Secure
- 60-79: Fair
- 40-59: Poor
- 0-39: Very Poor/Critical

### Recommendations

Analysis methods typically include recommendations for improving security.
