# Changelog

## Version 2.0 - Enhanced Security Tools

### New Features Added

#### 1. Two-Factor Authentication (2FA/TOTP) Module
- TOTP code generation and verification
- Secret key generation for authenticator apps
- QR code URL generation
- Time-based one-time password support

#### 2. Secure File Deletion Module
- Multi-pass file shredding (3+ passes)
- Gutmann method (35 passes) for maximum security
- Directory deletion support
- Configurable overwrite passes
- Data recovery prevention

#### 3. URL/Domain Security Checker Module
- Comprehensive URL analysis
- Phishing detection
- URL shortener expansion
- Domain reputation checking
- SSL certificate verification
- Risk scoring and assessment

#### 4. Email Security Analyzer Module
- Email header analysis
- SPF/DKIM/DMARC verification
- Phishing detection in email content
- Email spoofing detection
- URL extraction from emails
- Comprehensive security scoring

#### 5. Security Headers Checker Module
- HTTP security headers analysis
- Content Security Policy (CSP) validation
- HSTS checking
- Cookie security analysis
- Multiple URL checking
- Detailed security reports
- Improvement recommendations

### Improvements
- Enhanced main menu with 10 security tools
- Better error handling
- Improved user interface
- More comprehensive documentation

### Technical Details
- Added `two_factor_auth.py` module
- Added `secure_deletion.py` module
- Added `url_security.py` module
- Added `email_security.py` module
- Added `security_headers.py` module
- Updated `main.py` with new menu options
- Updated `requirements.txt` (added pyotp as optional)

## Version 1.0 - Initial Release

### Core Features
- Password Security Tools
- File Encryption/Decryption
- Network Security Scanner
- Security Utilities (Hash, Keys, Tokens)
- Data Privacy Tools
- Interactive Menu Interface
- Comprehensive Documentation
