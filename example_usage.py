"""
Example Usage Script
Demonstrates how to use various cybersecurity tools
"""

from password_security import PasswordSecurity
from file_encryption import FileEncryption
from network_security import NetworkSecurity
from security_utilities import SecurityUtilities
from data_privacy import DataPrivacy


def example_password_security():
    """Example: Password security operations"""
    print("\n" + "="*60)
    print("EXAMPLE: Password Security")
    print("="*60)
    
    ps = PasswordSecurity()
    
    # Check password strength
    test_passwords = ["password", "Password123", "MyStr0ng!P@ssw0rd"]
    for pwd in test_passwords:
        score, strength, feedback = ps.check_strength(pwd)
        print(f"\nPassword: {pwd}")
        print(f"Strength: {strength} ({score}/100)")
        print("Feedback:", ", ".join(feedback))
    
    # Generate secure password
    secure_password = ps.generate_password(length=16)
    print(f"\nGenerated Secure Password: {secure_password}")


def example_file_encryption():
    """Example: File encryption operations"""
    print("\n" + "="*60)
    print("EXAMPLE: File Encryption")
    print("="*60)
    
    fe = FileEncryption()
    
    # Encrypt a string
    plaintext = "This is a secret message!"
    password = "MySecurePassword123!"
    
    encrypted = fe.encrypt_string(plaintext, password)
    print(f"\nOriginal: {plaintext}")
    print(f"Encrypted: {encrypted}")
    
    decrypted = fe.decrypt_string(encrypted, password)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")


def example_network_security():
    """Example: Network security operations"""
    print("\n" + "="*60)
    print("EXAMPLE: Network Security")
    print("="*60)
    
    ns = NetworkSecurity()
    
    # Get local network info
    local_info = ns.get_local_network_info()
    print("\nLocal Network Information:")
    for key, value in local_info.items():
        print(f"  {key}: {value}")
    
    # Check a port (using example.com as it's reliable)
    host = "example.com"
    port = 80
    is_open, status = ns.check_port(host, port)
    print(f"\nPort Check ({host}:{port}): {status}")


def example_security_utilities():
    """Example: Security utilities"""
    print("\n" + "="*60)
    print("EXAMPLE: Security Utilities")
    print("="*60)
    
    su = SecurityUtilities()
    
    # Hash a string
    text = "Hello, World!"
    hash_value = su.hash_string(text, algorithm="sha256")
    print(f"\nText: {text}")
    print(f"SHA256 Hash: {hash_value}")
    
    # Generate API key
    api_key = su.generate_api_key()
    print(f"\nGenerated API Key: {api_key}")
    
    # Generate secret token
    token = su.generate_secret_token()
    print(f"Generated Token: {token}")


def example_data_privacy():
    """Example: Data privacy operations"""
    print("\n" + "="*60)
    print("EXAMPLE: Data Privacy")
    print("="*60)
    
    dp = DataPrivacy()
    
    # Detect sensitive data
    sample_text = """
    Contact Information:
    Email: john.doe@example.com
    Phone: 555-123-4567
    SSN: 123-45-6789
    Credit Card: 4532-1234-5678-9010
    """
    
    detected = dp.detect_sensitive_data(sample_text)
    print("\nDetected Sensitive Data:")
    for data_type, values in detected.items():
        print(f"  {data_type}: {values}")
    
    # Mask sensitive data
    print("\nMasked Information:")
    print(f"  Email: {dp.mask_email('john.doe@example.com')}")
    print(f"  Phone: {dp.mask_phone('555-123-4567')}")
    print(f"  SSN: {dp.mask_ssn('123-45-6789')}")
    print(f"  Credit Card: {dp.mask_credit_card('4532-1234-5678-9010')}")
    
    # Sanitize text
    sanitized = dp.sanitize_text(sample_text, mask_all=True)
    print("\nSanitized Text:")
    print(sanitized)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("CYBERSECURITY SOLUTIONS - EXAMPLE USAGE")
    print("="*60)
    
    try:
        example_password_security()
        example_file_encryption()
        example_network_security()
        example_security_utilities()
        example_data_privacy()
        
        print("\n" + "="*60)
        print("All examples completed successfully!")
        print("="*60 + "\n")
    
    except Exception as e:
        print(f"\nError running examples: {str(e)}")
        print("Make sure all dependencies are installed: pip install -r requirements.txt")
