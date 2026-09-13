# Cybersecurity Solutions Toolkit

A comprehensive cybersecurity toolkit designed to enhance online security, protect against threats, and ensure privacy and integrity of user data.

## Features

### 1. Password Security
- **Password Strength Checker**: Analyzes password strength with detailed feedback
- **Secure Password Generator**: Creates cryptographically secure passwords
- **Password Validation**: Validates passwords against security requirements

### 2. File Encryption/Decryption
- **AES-256 Encryption**: Industry-standard file encryption
- **PBKDF2 Key Derivation**: Secure key generation from passwords
- **String Encryption**: Encrypt/decrypt text strings
- **File Protection**: Encrypt sensitive files with password protection

### 3. Network Security Scanner
- **Port Scanning**: Check open/closed ports on hosts
- **SSL Certificate Check**: Verify website SSL certificates
- **DNS Security**: Check DNS resolution and security
- **Network Connectivity**: Ping hosts and check connectivity
- **Local Network Info**: Get local network configuration

### 4. Security Utilities
- **Hash Generation**: MD5, SHA1, SHA256, SHA512 hashing
- **File Hashing**: Generate file integrity hashes
- **API Key Generation**: Create secure API keys
- **Secret Tokens**: Generate cryptographically secure tokens
- **Password Hashing**: Argon2 password hashing (recommended)
- **CSRF Tokens**: Generate CSRF protection tokens
- **File Integrity Verification**: Compare and verify file hashes

### 5. Data Privacy Tools
- **Sensitive Data Detection**: Identify emails, phone numbers, SSNs, credit cards
- **Data Masking**: Mask sensitive information for privacy
- **Text Sanitization**: Sanitize text by masking sensitive data
- **Pseudonym Generation**: Create anonymous identifiers
- **Data Anonymization**: Anonymize specific fields in data structures

### 6. Two-Factor Authentication (2FA/TOTP)
- **TOTP Generation**: Generate time-based one-time passwords
- **Secret Key Generation**: Create secure secret keys for 2FA
- **Code Verification**: Verify TOTP codes
- **QR Code URL Generation**: Generate URLs for authenticator apps
- **Time Remaining**: Check time until next code generation

### 7. Secure File Deletion
- **File Shredding**: Securely delete files with multiple overwrite passes
- **Gutmann Method**: Advanced 35-pass deletion method
- **Directory Deletion**: Securely delete entire directories
- **Custom Passes**: Configurable overwrite passes
- **Data Recovery Prevention**: Makes file recovery extremely difficult

### 8. URL/Domain Security Checker
- **URL Analysis**: Comprehensive URL security analysis
- **Phishing Detection**: Detect suspicious URLs and patterns
- **URL Shortener Expansion**: Expand shortened URLs to see final destination
- **Domain Analysis**: Check domain security and reputation
- **Risk Assessment**: Security scoring and risk level determination
- **SSL Checking**: Verify SSL certificates for URLs

### 9. Email Security Analyzer
- **Header Analysis**: Analyze email headers for security issues
- **SPF/DKIM/DMARC Checking**: Verify email authentication
- **Phishing Detection**: Identify phishing indicators in email content
- **Spoofing Detection**: Detect email spoofing attempts
- **URL Extraction**: Extract URLs from emails for analysis
- **Comprehensive Analysis**: Full email security assessment

### 10. Security Headers Checker
- **HTTP Security Headers**: Check website security headers
- **CSP Analysis**: Content Security Policy validation
- **HSTS Checking**: Strict Transport Security verification
- **Cookie Security**: Analyze cookie security flags
- **Multiple URL Checking**: Check security headers for multiple URLs
- **Security Reports**: Generate detailed security reports
- **Recommendations**: Get recommendations for improving security

### 11. Security Audit & Log Analysis
- **Log File Analysis**: Analyze log files for security events
- **Brute Force Detection**: Detect brute force attack patterns
- **Access Log Analysis**: Analyze web server access logs
- **IP Extraction**: Extract IP addresses from logs
- **Event Counting**: Count security events by time period
- **Audit Reports**: Generate comprehensive security audit reports

### 12. Certificate Analyzer (Detailed)
- **Certificate Analysis**: Detailed SSL/TLS certificate analysis
- **Expiry Checking**: Check certificate expiration dates
- **Chain Verification**: Verify certificate chains
- **Security Scoring**: Rate certificate security
- **Multiple Certificate Checking**: Analyze multiple certificates
- **Certificate Reports**: Generate detailed certificate reports

### 13. Backup Verification
- **Backup Integrity**: Verify backup file integrity
- **Backup Comparison**: Compare two backup files
- **Manifest Creation**: Create backup manifests
- **Manifest Verification**: Verify backups against manifests
- **Backup Age Checking**: Check backup freshness
- **Backup Reports**: Generate backup verification reports

### 14. Security Configuration Checker
- **Password Policy Checking**: Check system password policies
- **File Permissions**: Analyze file permissions for security
- **Directory Permissions**: Check directory security
- **Environment Variables**: Check for sensitive environment variables
- **File Extensions**: Detect potentially dangerous file extensions
- **SSH Configuration**: Check SSH configuration security
- **Security Reports**: Generate security configuration reports

### 15. Phishing & Malicious URL Detection System
- **Advanced Phishing Detection**: Multi-method phishing URL detection
- **URL Structure Analysis**: Analyze URL patterns and structure
- **Domain Analysis**: Check domain characteristics and similarity
- **TLD Analysis**: Detect suspicious top-level domains
- **DNS Analysis**: Analyze DNS records for legitimacy
- **SSL Analysis**: Check SSL certificate validity
- **Content Analysis**: Analyze webpage content for phishing indicators
- **Batch Detection**: Analyze multiple URLs at once
- **Blacklist Checking**: Check URLs against blacklists

### 16. Intrusion Detection System (IDS)
- **Log Analysis**: Analyze log entries for intrusion indicators
- **Port Scan Detection**: Detect port scanning activities
- **Brute Force Detection**: Identify brute force attacks
- **Anomalous Traffic Detection**: Detect unusual network patterns
- **File Change Monitoring**: Monitor files for unauthorized changes
- **Alert Generation**: Generate security alerts
- **Real-time Monitoring**: Monitor system activities
- **IDS Reports**: Generate comprehensive IDS reports

### 17. Malware Detection Using Machine Learning
- **ML-based Detection**: Machine learning classification for malware
- **Feature Extraction**: Extract file features for analysis
- **Entropy Analysis**: Calculate file entropy (encrypted/packed detection)
- **Hash Matching**: Match against known malware databases
- **Directory Scanning**: Scan entire directories for malware
- **Batch Detection**: Analyze multiple files
- **Malware Reports**: Generate detailed malware detection reports
- **Database Integration**: Load and use malware hash databases

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

1. Clone or download this repository

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

Run the main application:
```bash
python main.py
```

The application provides an interactive menu-driven interface to access all security tools.

### Using Individual Modules

You can also import and use individual modules in your own Python scripts:

```python
from password_security import PasswordSecurity
from file_encryption import FileEncryption
from network_security import NetworkSecurity
from security_utilities import SecurityUtilities
from data_privacy import DataPrivacy

# Example: Check password strength
ps = PasswordSecurity()
score, strength, feedback = ps.check_strength("MyPassword123!")
print(f"Strength: {strength} ({score}/100)")

# Example: Generate secure password
password = ps.generate_password(length=20)
print(f"Generated password: {password}")

# Example: Encrypt a file
fe = FileEncryption()
fe.encrypt_file("sensitive.txt", "sensitive.enc", "my_password")

# Example: Hash a file
su = SecurityUtilities()
file_hash = su.hash_file("document.pdf", algorithm="sha256")
print(f"File hash: {file_hash}")
```

## Security Best Practices

1. **Passwords**:
   - Use generated passwords for accounts
   - Minimum 12 characters recommended
   - Use unique passwords for each account
   - Store passwords in a password manager

2. **File Encryption**:
   - Use strong, unique passwords for encryption
   - Securely store encryption passwords
   - Regularly backup encrypted files
   - Delete original files after encryption (when appropriate)

3. **Network Security**:
   - Only scan networks you own or have permission to scan
   - Use HTTPS for all web communications
   - Keep network services updated
   - Use firewalls and proper access controls

4. **Data Privacy**:
   - Mask sensitive data before sharing logs or reports
   - Use pseudonyms for user identification when possible
   - Regularly audit data for sensitive information
   - Follow GDPR and privacy regulations

## Modules Overview

### `password_security.py`
Password security operations including strength checking and generation.

### `file_encryption.py`
File and string encryption using AES-256 with PBKDF2 key derivation.

### `network_security.py`
Network scanning and security checking utilities.

### `security_utilities.py`
Hash generation, key generation, and other security utilities.

### `data_privacy.py`
Data privacy tools for detecting and masking sensitive information.

### `two_factor_auth.py`
Two-factor authentication and TOTP code generation.

### `secure_deletion.py`
Secure file deletion and shredding utilities.

### `url_security.py`
URL and domain security analysis and phishing detection.

### `email_security.py`
Email security analysis and header verification.

### `security_headers.py`
HTTP security headers checking and analysis.

### `security_audit.py`
Security audit and log analysis utilities.

### `certificate_analyzer.py`
Detailed SSL/TLS certificate analysis.

### `backup_verification.py`
Backup verification and integrity checking.

### `config_security.py`
Security configuration checking and analysis.

## Security Notes

- **Encryption**: Uses industry-standard AES-256 encryption
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Password Hashing**: Argon2 (recommended for password storage)
- **Random Generation**: Uses `secrets` module for cryptographically secure randomness
- **File Operations**: Includes proper error handling and validation

## Limitations

- Network scanning is basic and may not detect all security issues
- SSL checking does not perform full certificate chain validation
- File encryption is file-based, not disk-level encryption
- This toolkit is for educational and legitimate security purposes only

## Legal and Ethical Use

⚠️ **Important**: This toolkit is intended for:
- Personal security enhancement
- Educational purposes
- Legitimate security testing on systems you own or have permission to test
- Protecting your own data and systems

**DO NOT** use these tools to:
- Access systems without authorization
- Perform illegal activities
- Violate privacy or security of others
- Break laws or regulations

Users are responsible for ensuring their use complies with all applicable laws and regulations.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is provided as-is for educational and personal use.

## Support

For issues, questions, or suggestions, please create an issue in the repository.

---

**Stay Secure! 🔒**
