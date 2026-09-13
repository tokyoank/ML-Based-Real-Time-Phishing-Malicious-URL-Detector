"""
Security Utilities Module
Provides hash generation, key generation, and other security utilities
"""

import hashlib
import secrets
import base64
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class SecurityUtilities:
    """Provides various security utility functions"""
    
    def __init__(self):
        self.password_hasher = PasswordHasher()
    
    def hash_string(self, text: str, algorithm: str = 'sha256') -> str:
        """
        Hash a string using specified algorithm
        
        Args:
            text: String to hash
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
        Returns:
            Hexadecimal hash string
        """
        algorithm = algorithm.lower()
        
        if algorithm == 'md5':
            hasher = hashlib.md5()
        elif algorithm == 'sha1':
            hasher = hashlib.sha1()
        elif algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha512':
            hasher = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher.update(text.encode())
        return hasher.hexdigest()
    
    def hash_file(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Hash a file using specified algorithm
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
        Returns:
            Hexadecimal hash string or None if error
        """
        try:
            algorithm = algorithm.lower()
            
            if algorithm == 'md5':
                hasher = hashlib.md5()
            elif algorithm == 'sha1':
                hasher = hashlib.sha1()
            elif algorithm == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm == 'sha512':
                hasher = hashlib.sha512()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        
        except Exception as e:
            print(f"Error hashing file: {str(e)}")
            return None
    
    def generate_api_key(self, length: int = 32) -> str:
        """
        Generate a secure API key
        
        Args:
            length: Key length in bytes (default: 32)
        
        Returns:
            Base64 encoded API key
        """
        key = secrets.token_bytes(length)
        return base64.urlsafe_b64encode(key).decode().rstrip('=')
    
    def generate_secret_token(self, length: int = 32) -> str:
        """
        Generate a secure secret token
        
        Args:
            length: Token length (default: 32)
        
        Returns:
            Hexadecimal token string
        """
        return secrets.token_hex(length)
    
    def hash_password_argon2(self, password: str) -> str:
        """
        Hash password using Argon2 (recommended for password storage)
        
        Args:
            password: Password to hash
        
        Returns:
            Argon2 hash string
        """
        if not ARGON2_AVAILABLE or self.password_hasher is None:
            raise ImportError("argon2-cffi is not installed. Install it with: pip install argon2-cffi")
        return self.password_hasher.hash(password)
    
    def verify_password_argon2(self, password: str, hash_string: str) -> bool:
        """
        Verify password against Argon2 hash
        
        Args:
            password: Password to verify
            hash_string: Argon2 hash string
        
        Returns:
            True if password matches, False otherwise
        """
        if not ARGON2_AVAILABLE or self.password_hasher is None:
            raise ImportError("argon2-cffi is not installed. Install it with: pip install argon2-cffi")
        try:
            self.password_hasher.verify(hash_string, password)
            return True
        except Exception:
            return False
    
    def generate_csrf_token(self) -> str:
        """Generate a CSRF token"""
        return secrets.token_urlsafe(32)
    
    def generate_session_id(self) -> str:
        """Generate a secure session ID"""
        return secrets.token_urlsafe(32)
    
    def compare_files(self, file1_path: str, file2_path: str, algorithm: str = 'sha256') -> bool:
        """
        Compare two files by their hash values
        
        Args:
            file1_path: Path to first file
            file2_path: Path to second file
            algorithm: Hash algorithm to use
        
        Returns:
            True if files are identical, False otherwise
        """
        hash1 = self.hash_file(file1_path, algorithm)
        hash2 = self.hash_file(file2_path, algorithm)
        
        if hash1 is None or hash2 is None:
            return False
        
        return hash1 == hash2
    
    def verify_file_integrity(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify file integrity by comparing with expected hash
        
        Args:
            file_path: Path to file
            expected_hash: Expected hash value
            algorithm: Hash algorithm used
        
        Returns:
            True if hash matches, False otherwise
        """
        actual_hash = self.hash_file(file_path, algorithm)
        if actual_hash is None:
            return False
        
        return actual_hash.lower() == expected_hash.lower()
