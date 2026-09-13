# How to Run the Cybersecurity Solutions Toolkit

## Quick Start

1. **Open a terminal/command prompt** in the project directory:
   ```bash
   cd C:\Users\ankit\cybersecurity-solutions
   ```

2. **Install dependencies** (if not already installed):
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

## Using the Application

When you run the application, you'll see a menu with 14 security tools:

```
============================================================
     CYBERSECURITY SOLUTIONS TOOLKIT
============================================================
1. Password Security Tools
2. File Encryption/Decryption
3. Network Security Scanner
4. Security Utilities (Hash, Keys)
5. Data Privacy Tools
6. Two-Factor Authentication (2FA/TOTP)
7. Secure File Deletion
8. URL/Domain Security Checker
9. Email Security Analyzer
10. Security Headers Checker
11. Security Audit & Log Analysis
12. Certificate Analyzer (Detailed)
13. Backup Verification
14. Security Configuration Checker
15. Exit
============================================================
```

Simply enter the number (1-15) of the tool you want to use, and follow the prompts.

## Example Usage

### Example 1: Check Password Strength
1. Run: `python main.py`
2. Select option: `1`
3. Select option: `1` (Check Password Strength)
4. Enter a password when prompted
5. View the strength analysis

### Example 2: Generate a Secure Password
1. Run: `python main.py`
2. Select option: `1`
3. Select option: `2` (Generate Secure Password)
4. Enter desired length (or press Enter for default 16)
5. Copy the generated password

### Example 3: Encrypt a File
1. Run: `python main.py`
2. Select option: `2`
3. Select option: `1` (Encrypt File)
4. Enter file paths and password
5. File will be encrypted

## Tips

- Use option `15` to exit the application
- Each tool has its own submenu with multiple options
- Some tools require file paths - use absolute paths or paths relative to the project directory
- For network tools, ensure you have permission to scan the target
- For secure deletion, files are permanently deleted - use with caution!

## Troubleshooting

### Import Errors
If you get import errors, make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Permission Errors
Some operations (like file deletion, network scanning) may require appropriate permissions.

### File Not Found
Make sure you're using correct file paths. Use absolute paths if unsure.

## Running Examples

You can also run the example script to see demonstrations:
```bash
python example_usage.py
```

This will run examples of various tools without requiring user interaction.
