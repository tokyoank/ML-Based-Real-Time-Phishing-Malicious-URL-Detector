"""
Password Security Module
Provides password strength checking, generation, and validation
"""

import re
import secrets
import string
from typing import Tuple, List


class PasswordSecurity:
    """Handles password security operations"""
    
    def __init__(self):
        self.common_passwords = [
            "password", "123456", "123456789", "12345678", "12345",
            "1234567", "1234567890", "qwerty", "abc123", "monkey",
            "1234567890", "letmein", "trustno1", "dragon", "baseball",
            "iloveyou", "master", "sunshine", "ashley", "bailey"
        ]
    
    def check_strength(self, password: str) -> Tuple[int, str, List[str]]:
        """
        Check password strength and return score, feedback, and suggestions
        
        Returns:
            Tuple of (score 0-100, strength level, list of suggestions)
        """
        score = 0
        feedback = []
        
        # Length check
        length = len(password)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 5
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Character variety checks
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        score += char_types * 15
        
        if not has_lower:
            feedback.append("Add lowercase letters")
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_special:
            feedback.append("Add special characters")
        
        # Common password check
        if password.lower() in self.common_passwords:
            score -= 30
            feedback.append("Avoid common passwords")
        
        # Repeated characters check
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("Avoid repeating characters")
        
        # Sequential characters check
        sequences = ["abc", "123", "qwe", "asd", "zxc"]
        password_lower = password.lower()
        for seq in sequences:
            if seq in password_lower or seq[::-1] in password_lower:
                score -= 15
                feedback.append("Avoid sequential characters")
                break
        
        # Determine strength level
        score = max(0, min(100, score))
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        if not feedback:
            feedback.append("Password meets good security standards")
        
        return score, strength, feedback
    
    def generate_password(self, length: int = 16, include_upper: bool = True,
                         include_lower: bool = True, include_digits: bool = True,
                         include_special: bool = True) -> str:
        """
        Generate a secure random password
        
        Args:
            length: Password length (default: 16)
            include_upper: Include uppercase letters
            include_lower: Include lowercase letters
            include_digits: Include digits
            include_special: Include special characters
        
        Returns:
            Generated password string
        """
        characters = ""
        
        if include_lower:
            characters += string.ascii_lowercase
        if include_upper:
            characters += string.ascii_uppercase
        if include_digits:
            characters += string.digits
        if include_special:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            raise ValueError("At least one character type must be selected")
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        # Ensure at least one character from each selected type
        if include_lower and not any(c.islower() for c in password):
            password = password[:-1] + secrets.choice(string.ascii_lowercase)
        if include_upper and not any(c.isupper() for c in password):
            password = password[:-1] + secrets.choice(string.ascii_uppercase)
        if include_digits and not any(c.isdigit() for c in password):
            password = password[:-1] + secrets.choice(string.digits)
        if include_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            password = password[:-1] + secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
        
        # Shuffle the password to ensure randomness
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)
    
    def validate_password(self, password: str, min_length: int = 8) -> bool:
        """Validate if password meets minimum requirements"""
        if len(password) < min_length:
            return False
        
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
        
        return has_upper and has_lower and has_digit and has_special
