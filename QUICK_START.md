# Quick Start Guide

## Installation Steps

1. **Navigate to the project directory:**
   ```bash
   cd cybersecurity-solutions
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

Simply run:
```bash
python main.py
```

You'll see an interactive menu with all available tools.

## Quick Examples

### Example 1: Check Password Strength
```python
from password_security import PasswordSecurity

ps = PasswordSecurity()
score, strength, feedback = ps.check_strength("MyPassword123!")
print(f"Strength: {strength} ({score}/100)")
for suggestion in feedback:
    print(f"- {suggestion}")
```

### Example 2: Generate a Secure Password
```python
from password_security import PasswordSecurity

ps = PasswordSecurity()
password = ps.generate_password(length=20)
print(f"Your secure password: {password}")
```

### Example 3: Encrypt a File
```python
from file_encryption import FileEncryption

fe = FileEncryption()
fe.encrypt_file("document.txt", "document.enc", "your_strong_password")
print("File encrypted successfully!")
```

### Example 4: Hash a File
```python
from security_utilities import SecurityUtilities

su = SecurityUtilities()
file_hash = su.hash_file("important.pdf", algorithm="sha256")
print(f"File hash: {file_hash}")
```

### Example 5: Check Network Port
```python
from network_security import NetworkSecurity

ns = NetworkSecurity()
is_open, status = ns.check_port("google.com", 80)
print(status)
```

### Example 6: Detect Sensitive Data
```python
from data_privacy import DataPrivacy

dp = DataPrivacy()
text = "Contact me at john@example.com or call 555-123-4567"
detected = dp.detect_sensitive_data(text)
print(f"Detected: {detected}")
```

## Common Use Cases

### Secure File Storage
1. Use File Encryption to encrypt sensitive files
2. Store encrypted files securely
3. Use strong, unique passwords for encryption
4. Keep passwords in a secure password manager

### Password Management
1. Generate secure passwords using Password Generator
2. Check password strength before using
3. Store passwords securely (consider using a password manager)

### Network Security Audit
1. Scan common ports on your servers
2. Check SSL certificates for your websites
3. Verify DNS configuration
4. Monitor network connectivity

### Data Privacy Compliance
1. Use Data Privacy tools to detect sensitive information
2. Mask sensitive data before sharing logs/reports
3. Generate pseudonyms for user identification
4. Sanitize text before publication

## Troubleshooting

### Import Errors
If you get import errors, make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Argon2 Errors
If Argon2 is not available, install it separately:
```bash
pip install argon2-cffi
```

### Network Scanning Issues
- Some network operations may require administrator privileges
- Firewall settings may block certain scans
- Only scan networks you own or have permission to scan

## Next Steps

1. Read the full README.md for detailed documentation
2. Explore each module's functionality
3. Customize the code for your specific needs
4. Add additional security features as needed

## Security Reminders

- Always use strong, unique passwords
- Keep encryption keys and passwords secure
- Regularly update dependencies
- Only use on systems you own or have permission to test
- Follow all applicable laws and regulations
