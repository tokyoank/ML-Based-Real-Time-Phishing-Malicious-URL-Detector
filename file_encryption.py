"""
File Encryption Module
Provides secure file encryption and decryption using AES-256
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class FileEncryption:
    """Handles file encryption and decryption operations"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_file(self, input_file: str, output_file: str, password: str) -> bool:
        """
        Encrypt a file using AES-256
        
        Args:
            input_file: Path to file to encrypt
            output_file: Path for encrypted output file
            password: Encryption password
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate random salt
            salt = os.urandom(16)
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Read and encrypt file
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            # PKCS7 padding
            pad_length = 16 - (len(plaintext) % 16)
            plaintext += bytes([pad_length] * pad_length)
            
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Write encrypted file with salt and IV prepended
            with open(output_file, 'wb') as f:
                f.write(salt)
                f.write(iv)
                f.write(ciphertext)
            
            return True
        
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False
    
    def decrypt_file(self, input_file: str, output_file: str, password: str) -> bool:
        """
        Decrypt a file using AES-256
        
        Args:
            input_file: Path to encrypted file
            output_file: Path for decrypted output file
            password: Decryption password
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read encrypted file
            with open(input_file, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                ciphertext = f.read()
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            pad_length = plaintext[-1]
            plaintext = plaintext[:-pad_length]
            
            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            return True
        
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return False
    
    def encrypt_string(self, plaintext: str, password: str) -> str:
        """Encrypt a string and return base64 encoded result"""
        try:
            salt = os.urandom(16)
            key = self.derive_key(password, salt)
            iv = os.urandom(16)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Pad and encrypt
            plaintext_bytes = plaintext.encode()
            pad_length = 16 - (len(plaintext_bytes) % 16)
            plaintext_bytes += bytes([pad_length] * pad_length)
            
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            # Combine salt, IV, and ciphertext, then base64 encode
            combined = salt + iv + ciphertext
            return base64.b64encode(combined).decode()
        
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return ""
    
    def decrypt_string(self, encrypted_data: str, password: str) -> str:
        """Decrypt a base64 encoded string"""
        try:
            combined = base64.b64decode(encrypted_data)
            salt = combined[:16]
            iv = combined[16:32]
            ciphertext = combined[32:]
            
            key = self.derive_key(password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            pad_length = plaintext[-1]
            plaintext = plaintext[:-pad_length]
            
            return plaintext.decode()
        
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return ""
