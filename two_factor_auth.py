"""
Two-Factor Authentication (2FA/TOTP) Module
Provides TOTP code generation and verification
"""

import hmac
import hashlib
import time
import base64
from typing import Optional
from urllib.parse import quote
import secrets


class TwoFactorAuth:
    """Handles TOTP (Time-based One-Time Password) generation"""
    
    def __init__(self):
        self.time_step = 30  # Standard TOTP time step (30 seconds)
        self.digits = 6  # Standard number of digits
    
    def generate_secret_key(self, length: int = 32) -> str:
        """
        Generate a base32-encoded secret key for TOTP
        
        Args:
            length: Length of the secret key in bytes
        
        Returns:
            Base32-encoded secret key
        """
        secret_bytes = secrets.token_bytes(length)
        return base64.b32encode(secret_bytes).decode()
    
    def generate_totp(self, secret_key: str, time_step: int = None, digits: int = None) -> str:
        """
        Generate TOTP code from secret key
        
        Args:
            secret_key: Base32-encoded secret key
            time_step: Time step in seconds (default: 30)
            digits: Number of digits in code (default: 6)
        
        Returns:
            TOTP code as string
        """
        if time_step is None:
            time_step = self.time_step
        if digits is None:
            digits = self.digits
        
        try:
            # Decode the base32 secret key
            secret_bytes = base64.b32decode(secret_key.upper())
        except Exception:
            raise ValueError("Invalid secret key format. Must be base32 encoded.")
        
        # Get current time counter
        counter = int(time.time() / time_step)
        
        # Convert counter to bytes (8 bytes, big-endian)
        counter_bytes = counter.to_bytes(8, byteorder='big')
        
        # Generate HMAC-SHA1
        hmac_result = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_result[19] & 0x0F
        code = (
            ((hmac_result[offset] & 0x7F) << 24) |
            ((hmac_result[offset + 1] & 0xFF) << 16) |
            ((hmac_result[offset + 2] & 0xFF) << 8) |
            (hmac_result[offset + 3] & 0xFF)
        ) % (10 ** digits)
        
        # Format with leading zeros
        return str(code).zfill(digits)
    
    def verify_totp(self, secret_key: str, code: str, window: int = 1) -> bool:
        """
        Verify TOTP code
        
        Args:
            secret_key: Base32-encoded secret key
            code: TOTP code to verify
            window: Time window (default: 1, meaning ±1 time step)
        
        Returns:
            True if code is valid, False otherwise
        """
        current_code = self.generate_totp(secret_key)
        
        if code == current_code:
            return True
        
        # Check previous and next time steps if window > 0
        if window > 0:
            time_step = self.time_step
            
            # Try previous time steps
            for i in range(1, window + 1):
                previous_time = int(time.time() / time_step) - i
                previous_counter_bytes = previous_time.to_bytes(8, byteorder='big')
                
                try:
                    secret_bytes = base64.b32decode(secret_key.upper())
                    hmac_result = hmac.new(secret_bytes, previous_counter_bytes, hashlib.sha1).digest()
                    offset = hmac_result[19] & 0x0F
                    previous_code = (
                        ((hmac_result[offset] & 0x7F) << 24) |
                        ((hmac_result[offset + 1] & 0xFF) << 16) |
                        ((hmac_result[offset + 2] & 0xFF) << 8) |
                        (hmac_result[offset + 3] & 0xFF)
                    ) % (10 ** self.digits)
                    
                    if code == str(previous_code).zfill(self.digits):
                        return True
                except Exception:
                    continue
        
        return False
    
    def get_remaining_time(self) -> int:
        """
        Get remaining time until next TOTP code
        
        Returns:
            Remaining seconds
        """
        return self.time_step - (int(time.time()) % self.time_step)
    
    def generate_qr_url(self, secret_key: str, issuer: str, account_name: str) -> str:
        """
        Generate URL for QR code generation (for Google Authenticator, etc.)
        
        Args:
            secret_key: Base32-encoded secret key
            issuer: Service name (e.g., "MyApp")
            account_name: Account identifier (e.g., "user@example.com")
        
        Returns:
            otpauth URL for QR code
        """
        label = f"{issuer}:{account_name}"
        params = f"secret={secret_key}&issuer={quote(issuer)}"
        return f"otpauth://totp/{quote(label)}?{params}"
