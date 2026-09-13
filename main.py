"""
Cybersecurity Solutions - Main Application
A comprehensive cybersecurity toolkit
"""

import os
import sys
from datetime import datetime
from password_security import PasswordSecurity
from file_encryption import FileEncryption
from network_security import NetworkSecurity
from security_utilities import SecurityUtilities
from data_privacy import DataPrivacy
from two_factor_auth import TwoFactorAuth
from secure_deletion import SecureDeletion
from url_security import URLSecurity
from email_security import EmailSecurity
from security_headers import SecurityHeaders
from security_audit import SecurityAudit
from certificate_analyzer import CertificateAnalyzer
from backup_verification import BackupVerification
from config_security import ConfigSecurity
from phishing_detector import PhishingDetector
from intrusion_detection import IntrusionDetectionSystem
from malware_detector_ml import MalwareDetectorML
from email_spam_phishing import EmailSpamPhishingDetector
from keylogger_detector import KeyloggerDetector
from blockchain_voting import BlockchainVotingSystem
from evil_twin_detector import EvilTwinDetector
from colorama import init, Fore, Style

# Initialize colorama for Windows
init(autoreset=True)


class CyberSecurityToolkit:
    """Main application class for cybersecurity toolkit"""
    
    def __init__(self):
        self.password_security = PasswordSecurity()
        self.file_encryption = FileEncryption()
        self.network_security = NetworkSecurity()
        self.security_utilities = SecurityUtilities()
        self.data_privacy = DataPrivacy()
        self.two_factor_auth = TwoFactorAuth()
        self.secure_deletion = SecureDeletion()
        self.url_security = URLSecurity()
        self.email_security = EmailSecurity()
        self.security_headers = SecurityHeaders()
        self.security_audit = SecurityAudit()
        self.certificate_analyzer = CertificateAnalyzer()
        self.backup_verification = BackupVerification()
        self.config_security = ConfigSecurity()
        self.phishing_detector = PhishingDetector()
        self.ids = IntrusionDetectionSystem()
        self.malware_detector = MalwareDetectorML()
        self.email_spam_detector = EmailSpamPhishingDetector()
        self.keylogger_detector = KeyloggerDetector()
        self.voting_system = BlockchainVotingSystem()
        self.evil_twin_detector = EvilTwinDetector()
    
    def display_menu(self):
        """Display main menu"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}     CYBERSECURITY SOLUTIONS TOOLKIT")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Password Security Tools")
        print(f"{Fore.YELLOW}2.{Style.RESET_ALL} File Encryption/Decryption")
        print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Network Security Scanner")
        print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Security Utilities (Hash, Keys)")
        print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Data Privacy Tools")
        print(f"{Fore.YELLOW}6.{Style.RESET_ALL} Two-Factor Authentication (2FA/TOTP)")
        print(f"{Fore.YELLOW}7.{Style.RESET_ALL} Secure File Deletion")
        print(f"{Fore.YELLOW}8.{Style.RESET_ALL} URL/Domain Security Checker")
        print(f"{Fore.YELLOW}9.{Style.RESET_ALL} Email Security Analyzer")
        print(f"{Fore.YELLOW}10.{Style.RESET_ALL} Security Headers Checker")
        print(f"{Fore.YELLOW}11.{Style.RESET_ALL} Security Audit & Log Analysis")
        print(f"{Fore.YELLOW}12.{Style.RESET_ALL} Certificate Analyzer (Detailed)")
        print(f"{Fore.YELLOW}13.{Style.RESET_ALL} Backup Verification")
        print(f"{Fore.YELLOW}14.{Style.RESET_ALL} Security Configuration Checker")
        print(f"{Fore.YELLOW}15.{Style.RESET_ALL} Phishing & Malicious URL Detection")
        print(f"{Fore.YELLOW}16.{Style.RESET_ALL} Intrusion Detection System (IDS)")
        print(f"{Fore.YELLOW}17.{Style.RESET_ALL} Malware Detection (ML)")
        print(f"{Fore.YELLOW}18.{Style.RESET_ALL} Email Spam & Phishing Detection")
        print(f"{Fore.YELLOW}19.{Style.RESET_ALL} Keylogger Detection")
        print(f"{Fore.YELLOW}20.{Style.RESET_ALL} Blockchain Voting System")
        print(f"{Fore.YELLOW}21.{Style.RESET_ALL} Evil Twin / Fake Wi-Fi Detection")
        print(f"{Fore.YELLOW}22.{Style.RESET_ALL} Exit")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def password_menu(self):
        """Password security submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Password Security Tools ---{Style.RESET_ALL}")
            print("1. Check Password Strength")
            print("2. Generate Secure Password")
            print("3. Validate Password")
            print("4. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                password = input("Enter password to check: ")
                score, strength, feedback = self.password_security.check_strength(password)
                
                color = Fore.GREEN if score >= 60 else Fore.YELLOW if score >= 40 else Fore.RED
                print(f"\n{Fore.CYAN}Password Strength: {color}{strength} ({score}/100){Style.RESET_ALL}")
                print(f"{Fore.CYAN}Feedback:{Style.RESET_ALL}")
                for item in feedback:
                    print(f"  - {item}")
            
            elif choice == '2':
                try:
                    length = int(input("Password length (default 16): ") or "16")
                    password = self.password_security.generate_password(length=length)
                    print(f"\n{Fore.GREEN}Generated Password: {password}{Style.RESET_ALL}")
                except ValueError as e:
                    print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            
            elif choice == '3':
                password = input("Enter password to validate: ")
                is_valid = self.password_security.validate_password(password)
                status = f"{Fore.GREEN}VALID{Style.RESET_ALL}" if is_valid else f"{Fore.RED}INVALID{Style.RESET_ALL}"
                print(f"\nPassword Status: {status}")
            
            elif choice == '4':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def encryption_menu(self):
        """File encryption submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- File Encryption/Decryption ---{Style.RESET_ALL}")
            print("1. Encrypt File")
            print("2. Decrypt File")
            print("3. Encrypt String")
            print("4. Decrypt String")
            print("5. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                input_file = input("Enter file path to encrypt: ")
                output_file = input("Enter output file path: ")
                password = input("Enter encryption password: ")
                
                if self.file_encryption.encrypt_file(input_file, output_file, password):
                    print(f"{Fore.GREEN}File encrypted successfully!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Encryption failed!{Style.RESET_ALL}")
            
            elif choice == '2':
                input_file = input("Enter encrypted file path: ")
                output_file = input("Enter output file path: ")
                password = input("Enter decryption password: ")
                
                if self.file_encryption.decrypt_file(input_file, output_file, password):
                    print(f"{Fore.GREEN}File decrypted successfully!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Decryption failed!{Style.RESET_ALL}")
            
            elif choice == '3':
                text = input("Enter text to encrypt: ")
                password = input("Enter encryption password: ")
                encrypted = self.file_encryption.encrypt_string(text, password)
                if encrypted:
                    print(f"\n{Fore.GREEN}Encrypted: {encrypted}{Style.RESET_ALL}")
            
            elif choice == '4':
                encrypted = input("Enter encrypted text: ")
                password = input("Enter decryption password: ")
                decrypted = self.file_encryption.decrypt_string(encrypted, password)
                if decrypted:
                    print(f"\n{Fore.GREEN}Decrypted: {decrypted}{Style.RESET_ALL}")
            
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def network_menu(self):
        """Network security submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Network Security Scanner ---{Style.RESET_ALL}")
            print("1. Check Single Port")
            print("2. Scan Common Ports")
            print("3. Check Website SSL")
            print("4. Check DNS Security")
            print("5. Ping Host")
            print("6. Get Local Network Info")
            print("7. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                host = input("Enter hostname or IP: ")
                port = int(input("Enter port number: "))
                is_open, status = self.network_security.check_port(host, port)
                color = Fore.GREEN if is_open else Fore.RED
                print(f"\n{color}{status}{Style.RESET_ALL}")
            
            elif choice == '2':
                host = input("Enter hostname or IP: ")
                results = self.network_security.scan_common_ports(host)
                print(f"\n{Fore.CYAN}Port Scan Results for {host}:{Style.RESET_ALL}")
                for port, (is_open, status) in results.items():
                    color = Fore.GREEN if is_open else Fore.RED
                    print(f"  {color}{status}{Style.RESET_ALL}")
            
            elif choice == '3':
                url = input("Enter website URL: ")
                result = self.network_security.check_website_ssl(url)
                print(f"\n{Fore.CYAN}SSL Check Results:{Style.RESET_ALL}")
                for key, value in result.items():
                    print(f"  {key}: {value}")
            
            elif choice == '4':
                domain = input("Enter domain name: ")
                result = self.network_security.check_dns_security(domain)
                print(f"\n{Fore.CYAN}DNS Security Results:{Style.RESET_ALL}")
                for key, value in result.items():
                    print(f"  {key}: {value}")
            
            elif choice == '5':
                host = input("Enter hostname or IP: ")
                result = self.network_security.ping_host(host)
                color = Fore.GREEN if result['reachable'] else Fore.RED
                print(f"\n{color}Host {'reachable' if result['reachable'] else 'unreachable'}{Style.RESET_ALL}")
                if result.get('error'):
                    print(f"{Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
            
            elif choice == '6':
                info = self.network_security.get_local_network_info()
                print(f"\n{Fore.CYAN}Local Network Information:{Style.RESET_ALL}")
                for key, value in info.items():
                    print(f"  {key}: {value}")
            
            elif choice == '7':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def utilities_menu(self):
        """Security utilities submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Security Utilities ---{Style.RESET_ALL}")
            print("1. Hash String")
            print("2. Hash File")
            print("3. Generate API Key")
            print("4. Generate Secret Token")
            print("5. Hash Password (Argon2)")
            print("6. Verify Password (Argon2)")
            print("7. Generate CSRF Token")
            print("8. Compare Files")
            print("9. Verify File Integrity")
            print("10. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                text = input("Enter text to hash: ")
                algorithm = input("Algorithm (md5/sha1/sha256/sha512, default sha256): ") or "sha256"
                hash_value = self.security_utilities.hash_string(text, algorithm)
                print(f"\n{Fore.GREEN}Hash ({algorithm}): {hash_value}{Style.RESET_ALL}")
            
            elif choice == '2':
                file_path = input("Enter file path: ")
                algorithm = input("Algorithm (md5/sha1/sha256/sha512, default sha256): ") or "sha256"
                hash_value = self.security_utilities.hash_file(file_path, algorithm)
                if hash_value:
                    print(f"\n{Fore.GREEN}File Hash ({algorithm}): {hash_value}{Style.RESET_ALL}")
            
            elif choice == '3':
                length = int(input("Key length in bytes (default 32): ") or "32")
                key = self.security_utilities.generate_api_key(length)
                print(f"\n{Fore.GREEN}API Key: {key}{Style.RESET_ALL}")
            
            elif choice == '4':
                length = int(input("Token length (default 32): ") or "32")
                token = self.security_utilities.generate_secret_token(length)
                print(f"\n{Fore.GREEN}Secret Token: {token}{Style.RESET_ALL}")
            
            elif choice == '5':
                password = input("Enter password to hash: ")
                hash_value = self.security_utilities.hash_password_argon2(password)
                print(f"\n{Fore.GREEN}Argon2 Hash: {hash_value}{Style.RESET_ALL}")
            
            elif choice == '6':
                password = input("Enter password: ")
                hash_string = input("Enter hash string: ")
                is_valid = self.security_utilities.verify_password_argon2(password, hash_string)
                status = f"{Fore.GREEN}VALID{Style.RESET_ALL}" if is_valid else f"{Fore.RED}INVALID{Style.RESET_ALL}"
                print(f"\nPassword Status: {status}")
            
            elif choice == '7':
                token = self.security_utilities.generate_csrf_token()
                print(f"\n{Fore.GREEN}CSRF Token: {token}{Style.RESET_ALL}")
            
            elif choice == '8':
                file1 = input("Enter first file path: ")
                file2 = input("Enter second file path: ")
                are_same = self.security_utilities.compare_files(file1, file2)
                status = f"{Fore.GREEN}Files are IDENTICAL{Style.RESET_ALL}" if are_same else f"{Fore.RED}Files are DIFFERENT{Style.RESET_ALL}"
                print(f"\n{status}")
            
            elif choice == '9':
                file_path = input("Enter file path: ")
                expected_hash = input("Enter expected hash: ")
                algorithm = input("Algorithm (md5/sha1/sha256/sha512, default sha256): ") or "sha256"
                is_valid = self.security_utilities.verify_file_integrity(file_path, expected_hash, algorithm)
                status = f"{Fore.GREEN}File integrity VERIFIED{Style.RESET_ALL}" if is_valid else f"{Fore.RED}File integrity FAILED{Style.RESET_ALL}"
                print(f"\n{status}")
            
            elif choice == '10':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def privacy_menu(self):
        """Data privacy submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Data Privacy Tools ---{Style.RESET_ALL}")
            print("1. Detect Sensitive Data")
            print("2. Mask Email")
            print("3. Mask Phone Number")
            print("4. Mask SSN")
            print("5. Mask Credit Card")
            print("6. Sanitize Text")
            print("7. Generate Pseudonym")
            print("8. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                text = input("Enter text to analyze: ")
                detected = self.data_privacy.detect_sensitive_data(text)
                if detected:
                    print(f"\n{Fore.CYAN}Detected Sensitive Data:{Style.RESET_ALL}")
                    for data_type, values in detected.items():
                        print(f"  {data_type}: {values}")
                else:
                    print(f"\n{Fore.GREEN}No sensitive data detected{Style.RESET_ALL}")
            
            elif choice == '2':
                email = input("Enter email address: ")
                masked = self.data_privacy.mask_email(email)
                print(f"\n{Fore.GREEN}Masked: {masked}{Style.RESET_ALL}")
            
            elif choice == '3':
                phone = input("Enter phone number: ")
                masked = self.data_privacy.mask_phone(phone)
                print(f"\n{Fore.GREEN}Masked: {masked}{Style.RESET_ALL}")
            
            elif choice == '4':
                ssn = input("Enter SSN: ")
                masked = self.data_privacy.mask_ssn(ssn)
                print(f"\n{Fore.GREEN}Masked: {masked}{Style.RESET_ALL}")
            
            elif choice == '5':
                card = input("Enter credit card number: ")
                masked = self.data_privacy.mask_credit_card(card)
                print(f"\n{Fore.GREEN}Masked: {masked}{Style.RESET_ALL}")
            
            elif choice == '6':
                text = input("Enter text to sanitize: ")
                sanitized = self.data_privacy.sanitize_text(text, mask_all=True)
                print(f"\n{Fore.GREEN}Sanitized Text:{Style.RESET_ALL}")
                print(sanitized)
            
            elif choice == '7':
                identifier = input("Enter identifier: ")
                salt = input("Enter salt (optional): ") or ""
                pseudonym = self.data_privacy.generate_pseudonym(identifier, salt)
                print(f"\n{Fore.GREEN}Pseudonym: {pseudonym}{Style.RESET_ALL}")
            
            elif choice == '8':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def two_factor_menu(self):
        """Two-factor authentication submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Two-Factor Authentication (2FA/TOTP) ---{Style.RESET_ALL}")
            print("1. Generate Secret Key")
            print("2. Generate TOTP Code")
            print("3. Verify TOTP Code")
            print("4. Get Remaining Time")
            print("5. Generate QR Code URL")
            print("6. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                length = int(input("Secret key length in bytes (default 32): ") or "32")
                secret_key = self.two_factor_auth.generate_secret_key(length)
                print(f"\n{Fore.GREEN}Secret Key: {secret_key}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Keep this key secure! Use it with authenticator apps.{Style.RESET_ALL}")
            
            elif choice == '2':
                secret_key = input("Enter secret key: ")
                try:
                    code = self.two_factor_auth.generate_totp(secret_key)
                    remaining = self.two_factor_auth.get_remaining_time()
                    print(f"\n{Fore.GREEN}TOTP Code: {code}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Valid for {remaining} more seconds{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            
            elif choice == '3':
                secret_key = input("Enter secret key: ")
                code = input("Enter TOTP code to verify: ")
                is_valid = self.two_factor_auth.verify_totp(secret_key, code)
                status = f"{Fore.GREEN}VALID{Style.RESET_ALL}" if is_valid else f"{Fore.RED}INVALID{Style.RESET_ALL}"
                print(f"\nCode Status: {status}")
            
            elif choice == '4':
                remaining = self.two_factor_auth.get_remaining_time()
                print(f"\n{Fore.CYAN}Remaining time until next code: {remaining} seconds{Style.RESET_ALL}")
            
            elif choice == '5':
                secret_key = input("Enter secret key: ")
                issuer = input("Enter service name (e.g., MyApp): ")
                account_name = input("Enter account identifier (e.g., user@example.com): ")
                qr_url = self.two_factor_auth.generate_qr_url(secret_key, issuer, account_name)
                print(f"\n{Fore.GREEN}QR Code URL:{Style.RESET_ALL}")
                print(qr_url)
                print(f"\n{Fore.CYAN}Use this URL with QR code generators for authenticator apps{Style.RESET_ALL}")
            
            elif choice == '6':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def secure_deletion_menu(self):
        """Secure file deletion submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Secure File Deletion ---{Style.RESET_ALL}")
            print("1. Shred File (Standard - 3 passes)")
            print("2. Shred File (Custom passes)")
            print("3. Shred File (Gutmann method - 35 passes)")
            print("4. Shred Directory")
            print("5. Back to Main Menu")
            print(f"{Fore.RED}WARNING: This permanently deletes files!{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                file_path = input("Enter file path to securely delete: ")
                confirm = input(f"{Fore.RED}Are you sure? This cannot be undone! (yes/no): {Style.RESET_ALL}")
                if confirm.lower() == 'yes':
                    if self.secure_deletion.shred_file(file_path, verbose=True):
                        print(f"{Fore.GREEN}File securely deleted!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Deletion failed!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
            
            elif choice == '2':
                file_path = input("Enter file path to securely delete: ")
                passes = int(input("Number of overwrite passes (default 3): ") or "3")
                confirm = input(f"{Fore.RED}Are you sure? This cannot be undone! (yes/no): {Style.RESET_ALL}")
                if confirm.lower() == 'yes':
                    if self.secure_deletion.shred_file(file_path, passes=passes, verbose=True):
                        print(f"{Fore.GREEN}File securely deleted!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Deletion failed!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
            
            elif choice == '3':
                file_path = input("Enter file path to securely delete: ")
                confirm = input(f"{Fore.RED}Are you sure? This cannot be undone! (yes/no): {Style.RESET_ALL}")
                if confirm.lower() == 'yes':
                    if self.secure_deletion.shred_file_gutmann(file_path, verbose=True):
                        print(f"{Fore.GREEN}File securely deleted (Gutmann method)!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Deletion failed!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
            
            elif choice == '4':
                dir_path = input("Enter directory path to securely delete: ")
                confirm = input(f"{Fore.RED}Are you sure? This will delete all files in the directory! (yes/no): {Style.RESET_ALL}")
                if confirm.lower() == 'yes':
                    if self.secure_deletion.shred_directory(dir_path, verbose=True):
                        print(f"{Fore.GREEN}Directory securely deleted!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Deletion failed!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Operation cancelled{Style.RESET_ALL}")
            
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def url_security_menu(self):
        """URL security submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- URL/Domain Security Checker ---{Style.RESET_ALL}")
            print("1. Analyze URL")
            print("2. Check URL Reputation")
            print("3. Expand Short URL")
            print("4. Validate URL Format")
            print("5. Analyze Domain")
            print("6. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                url = input("Enter URL to analyze: ")
                result = self.url_security.analyze_url(url)
                print(f"\n{Fore.CYAN}URL Analysis Results:{Style.RESET_ALL}")
                print(f"  Security Score: {result['security_score']}/100")
                print(f"  Risk Level: {result.get('risk_level', 'Unknown')}")
                print(f"  Is Safe: {'Yes' if result['is_safe'] else 'No'}")
                if result.get('warnings'):
                    print(f"\n  Warnings:")
                    for warning in result['warnings']:
                        print(f"    ⚠ {warning}")
                if result.get('suggestions'):
                    print(f"\n  Suggestions:")
                    for suggestion in result['suggestions']:
                        print(f"    → {suggestion}")
                if result.get('domain_info'):
                    print(f"\n  Domain Info:")
                    for key, value in result['domain_info'].items():
                        print(f"    {key}: {value}")
            
            elif choice == '2':
                url = input("Enter URL to check: ")
                result = self.url_security.check_url_reputation(url)
                print(f"\n{Fore.CYAN}URL Reputation:{Style.RESET_ALL}")
                print(f"  Reputation: {result['reputation']}")
                print(f"  Security Score: {result['security_score']}/100")
                print(f"  Risk Level: {result['risk_level']}")
                if result.get('warnings'):
                    for warning in result['warnings']:
                        print(f"  ⚠ {warning}")
            
            elif choice == '3':
                url = input("Enter shortened URL: ")
                expanded = self.url_security.expand_short_url(url)
                if expanded:
                    print(f"\n{Fore.GREEN}Expanded URL: {expanded}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Could not expand URL{Style.RESET_ALL}")
            
            elif choice == '4':
                url = input("Enter URL to validate: ")
                is_valid, message = self.url_security.validate_url_format(url)
                color = Fore.GREEN if is_valid else Fore.RED
                print(f"\n{color}{message}{Style.RESET_ALL}")
            
            elif choice == '5':
                domain = input("Enter domain name: ")
                info = self.url_security.analyze_domain(domain)
                print(f"\n{Fore.CYAN}Domain Analysis:{Style.RESET_ALL}")
                for key, value in info.items():
                    print(f"  {key}: {value}")
            
            elif choice == '6':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def email_security_menu(self):
        """Email security submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Email Security Analyzer ---{Style.RESET_ALL}")
            print("1. Analyze Email Headers")
            print("2. Analyze Email Content")
            print("3. Analyze Full Email")
            print("4. Check Email Address")
            print("5. Extract URLs from Email")
            print("6. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                print(f"{Fore.CYAN}Paste email content (headers + body), then press Enter twice:{Style.RESET_ALL}")
                lines = []
                while True:
                    line = input()
                    if line == "" and lines and lines[-1] == "":
                        break
                    lines.append(line)
                email_content = "\n".join(lines)
                result = self.email_security.analyze_email_headers(email_content)
                print(f"\n{Fore.CYAN}Header Analysis Results:{Style.RESET_ALL}")
                print(f"  Security Score: {result['security_score']}/100")
                if result.get('header_info'):
                    print(f"\n  Header Information:")
                    for key, value in result['header_info'].items():
                        if value:
                            print(f"    {key}: {value}")
                if result.get('warnings'):
                    print(f"\n  Warnings:")
                    for warning in result['warnings']:
                        print(f"    ⚠ {warning}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '2':
                body = input("Enter email body text: ")
                result = self.email_security.analyze_email_content(body)
                print(f"\n{Fore.CYAN}Content Analysis:{Style.RESET_ALL}")
                print(f"  Phishing Score: {result['phishing_score']}/100")
                print(f"  Risk Level: {result['risk_level']}")
                if result.get('suspicious_patterns'):
                    print(f"\n  Suspicious Patterns:")
                    for pattern in result['suspicious_patterns']:
                        print(f"    ⚠ {pattern}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '3':
                print(f"{Fore.CYAN}Paste full email content, then press Enter twice:{Style.RESET_ALL}")
                lines = []
                while True:
                    line = input()
                    if line == "" and lines and lines[-1] == "":
                        break
                    lines.append(line)
                email_content = "\n".join(lines)
                result = self.email_security.analyze_full_email(email_content)
                print(f"\n{Fore.CYAN}Full Email Analysis:{Style.RESET_ALL}")
                print(f"  Overall Risk: {result['overall_risk']}")
                if result.get('header_analysis'):
                    print(f"  Header Security Score: {result['header_analysis'].get('security_score', 'N/A')}/100")
                if result.get('content_analysis'):
                    print(f"  Content Phishing Score: {result['content_analysis'].get('phishing_score', 0)}/100")
                if result.get('urls_found'):
                    print(f"\n  URLs Found: {len(result['urls_found'])}")
                    for url in result['urls_found'][:5]:  # Show first 5
                        print(f"    - {url}")
            
            elif choice == '4':
                email = input("Enter email address: ")
                result = self.email_security.check_email_address(email)
                print(f"\n{Fore.CYAN}Email Address Check:{Style.RESET_ALL}")
                print(f"  Valid: {'Yes' if result['is_valid'] else 'No'}")
                if result.get('domain'):
                    print(f"  Domain: {result['domain']}")
                if result.get('warnings'):
                    for warning in result['warnings']:
                        print(f"  ⚠ {warning}")
            
            elif choice == '5':
                print(f"{Fore.CYAN}Paste email content, then press Enter twice:{Style.RESET_ALL}")
                lines = []
                while True:
                    line = input()
                    if line == "" and lines and lines[-1] == "":
                        break
                    lines.append(line)
                email_content = "\n".join(lines)
                urls = self.email_security.extract_urls_from_email(email_content)
                print(f"\n{Fore.CYAN}URLs Found ({len(urls)}):{Style.RESET_ALL}")
                for url in urls:
                    print(f"  - {url}")
            
            elif choice == '6':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def security_headers_menu(self):
        """Security headers submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Security Headers Checker ---{Style.RESET_ALL}")
            print("1. Check Security Headers")
            print("2. Generate Security Report")
            print("3. Check Multiple URLs")
            print("4. Get Header Description")
            print("5. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                url = input("Enter website URL: ")
                result = self.security_headers.check_security_headers(url)
                print(f"\n{Fore.CYAN}Security Headers Analysis:{Style.RESET_ALL}")
                print(f"  Security Score: {result['security_score']}/100")
                print(f"  Security Level: {result['security_level']}")
                print(f"\n  Headers Present ({len(result['headers_present'])}):")
                for header, value in result['headers_present'].items():
                    print(f"    ✓ {header}: {value[:80]}...")
                if result.get('headers_missing'):
                    print(f"\n  Missing Headers ({len(result['headers_missing'])}):")
                    for header in result['headers_missing']:
                        print(f"    ✗ {header}")
                if result.get('warnings'):
                    print(f"\n  Warnings:")
                    for warning in result['warnings']:
                        print(f"    ⚠ {warning}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations'][:5]:  # Show first 5
                        print(f"    → {rec}")
            
            elif choice == '2':
                url = input("Enter website URL: ")
                report = self.security_headers.generate_security_report(url)
                print(report)
            
            elif choice == '3':
                urls_input = input("Enter URLs (comma-separated): ")
                urls = [url.strip() for url in urls_input.split(',')]
                results = self.security_headers.check_multiple_urls(urls)
                print(f"\n{Fore.CYAN}Multiple URL Analysis:{Style.RESET_ALL}")
                for url, result in results.items():
                    print(f"\n  {url}:")
                    print(f"    Score: {result['security_score']}/100")
                    print(f"    Level: {result['security_level']}")
                    print(f"    Headers: {len(result['headers_present'])}/{len(self.security_headers.important_headers)}")
            
            elif choice == '4':
                header_name = input("Enter header name: ")
                description = self.security_headers.get_header_description(header_name)
                print(f"\n{Fore.CYAN}{header_name}:{Style.RESET_ALL}")
                print(f"  {description}")
            
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def security_audit_menu(self):
        """Security audit submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Security Audit & Log Analysis ---{Style.RESET_ALL}")
            print("1. Analyze Log File")
            print("2. Detect Brute Force Attacks")
            print("3. Analyze Access Logs")
            print("4. Generate Audit Report")
            print("5. Extract IPs from Log")
            print("6. Count Events by Time")
            print("7. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                log_file = input("Enter log file path: ")
                pattern_type = input("Pattern type (all/failed_login/suspicious_activity/sql_injection/xss_attempts/path_traversal, default all): ") or "all"
                result = self.security_audit.analyze_log_file(log_file, pattern_type)
                print(f"\n{Fore.CYAN}Log Analysis Results:{Style.RESET_ALL}")
                print(f"  Total Lines: {result['total_lines']}")
                print(f"  Matches Found: {result.get('match_count', 0)}")
                print(f"  Severity: {result['severity'].upper()}")
                if result.get('matches'):
                    for pattern_type, matches in result['matches'].items():
                        print(f"\n  {pattern_type}: {len(matches)} matches")
                        for match in matches[:3]:
                            print(f"    Line {match['line']}: {match['content']}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '2':
                log_file = input("Enter log file path: ")
                threshold = int(input("Brute force threshold (default 10): ") or "10")
                result = self.security_audit.detect_brute_force(log_file, threshold)
                if result.get('brute_force_detected'):
                    print(f"\n{Fore.RED}BRUTE FORCE DETECTED!{Style.RESET_ALL}")
                    for ip_info in result['suspicious_ips']:
                        print(f"  IP: {ip_info['ip']} - {ip_info['attempts']} attempts ({ip_info['severity']})")
                else:
                    print(f"\n{Fore.GREEN}No brute force attacks detected{Style.RESET_ALL}")
            
            elif choice == '3':
                log_file = input("Enter access log file path: ")
                result = self.security_audit.analyze_access_logs(log_file)
                print(f"\n{Fore.CYAN}Access Log Analysis:{Style.RESET_ALL}")
                print(f"  Total Requests: {result['total_requests']}")
                print(f"  Status Codes: {dict(result['status_codes'])}")
                print(f"  Top IPs: {dict(list(result['top_ips'].items())[:5])}")
                if result.get('suspicious_requests'):
                    print(f"  Suspicious Requests: {len(result['suspicious_requests'])}")
            
            elif choice == '4':
                log_file = input("Enter log file path: ")
                report = self.security_audit.generate_audit_report(log_file)
                print(report)
            
            elif choice == '5':
                log_file = input("Enter log file path: ")
                ips = self.security_audit.extract_ips_from_log(log_file)
                print(f"\n{Fore.CYAN}Unique IPs Found ({len(ips)}):{Style.RESET_ALL}")
                for ip in ips[:20]:
                    print(f"  {ip}")
            
            elif choice == '6':
                log_file = input("Enter log file path: ")
                events = self.security_audit.count_events_by_time(log_file)
                print(f"\n{Fore.CYAN}Events by Time:{Style.RESET_ALL}")
                for time_period, count in sorted(events.items())[:20]:
                    print(f"  {time_period}: {count} events")
            
            elif choice == '7':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def certificate_analyzer_menu(self):
        """Certificate analyzer submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Certificate Analyzer (Detailed) ---{Style.RESET_ALL}")
            print("1. Analyze Certificate")
            print("2. Check Certificate Chain")
            print("3. Get Certificate Expiry")
            print("4. Generate Certificate Report")
            print("5. Check Certificate from URL")
            print("6. Check Multiple Certificates")
            print("7. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                hostname = input("Enter hostname: ")
                port = int(input("Enter port (default 443): ") or "443")
                result = self.certificate_analyzer.analyze_certificate(hostname, port)
                print(f"\n{Fore.CYAN}Certificate Analysis:{Style.RESET_ALL}")
                print(f"  Certificate Found: {'✓' if result['certificate_found'] else '✗'}")
                print(f"  Valid: {'✓' if result['valid'] else '✗'}")
                print(f"  Expired: {'✗ Yes' if result['expired'] else '✓ No'}")
                print(f"  Security Score: {result['security_score']}/100")
                if result.get('certificate_info'):
                    for key, value in result['certificate_info'].items():
                        if key != 'subject_alt_names':
                            print(f"  {key.replace('_', ' ').title()}: {value}")
                if result.get('warnings'):
                    for warning in result['warnings']:
                        print(f"  ⚠ {warning}")
            
            elif choice == '2':
                hostname = input("Enter hostname: ")
                port = int(input("Enter port (default 443): ") or "443")
                result = self.certificate_analyzer.check_certificate_chain(hostname, port)
                print(f"\n{Fore.CYAN}Certificate Chain:{Style.RESET_ALL}")
                print(f"  Chain Length: {result['chain_length']}")
                print(f"  Root Trusted: {'✓' if result['root_trusted'] else '✗'}")
            
            elif choice == '3':
                hostname = input("Enter hostname: ")
                port = int(input("Enter port (default 443): ") or "443")
                expiry = self.certificate_analyzer.get_certificate_expiry_date(hostname, port)
                if expiry:
                    print(f"\n{Fore.GREEN}Certificate Expires: {expiry}{Style.RESET_ALL}")
                    days_left = (expiry - datetime.now()).days
                    print(f"  Days Remaining: {days_left}")
                else:
                    print(f"{Fore.RED}Could not retrieve expiry date{Style.RESET_ALL}")
            
            elif choice == '4':
                hostname = input("Enter hostname: ")
                port = int(input("Enter port (default 443): ") or "443")
                report = self.certificate_analyzer.generate_certificate_report(hostname, port)
                print(report)
            
            elif choice == '5':
                url = input("Enter URL: ")
                result = self.certificate_analyzer.check_certificate_from_url(url)
                print(f"\n{Fore.CYAN}Certificate Analysis:{Style.RESET_ALL}")
                print(f"  Valid: {'✓' if result['valid'] else '✗'}")
                print(f"  Security Score: {result['security_score']}/100")
            
            elif choice == '6':
                urls_input = input("Enter hostnames (comma-separated): ")
                hostnames = [h.strip() for h in urls_input.split(',')]
                results = self.certificate_analyzer.check_multiple_certificates(hostnames)
                print(f"\n{Fore.CYAN}Multiple Certificate Analysis:{Style.RESET_ALL}")
                for hostname, result in results.items():
                    print(f"\n  {hostname}:")
                    print(f"    Valid: {'✓' if result['valid'] else '✗'}")
                    print(f"    Score: {result['security_score']}/100")
            
            elif choice == '7':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def backup_verification_menu(self):
        """Backup verification submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Backup Verification ---{Style.RESET_ALL}")
            print("1. Verify Backup Integrity")
            print("2. Compare Two Backups")
            print("3. Create Backup Manifest")
            print("4. Verify Backup Against Manifest")
            print("5. Check Backup Age")
            print("6. Generate Backup Report")
            print("7. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                backup_file = input("Enter backup file path: ")
                original_hash = input("Enter original hash (optional): ") or None
                result = self.backup_verification.verify_backup_integrity(backup_file, original_hash)
                print(f"\n{Fore.CYAN}Backup Verification:{Style.RESET_ALL}")
                print(f"  Exists: {'✓' if result['exists'] else '✗'}")
                print(f"  Size: {result.get('size', 0):,} bytes")
                print(f"  Integrity: {result['integrity'].upper()}")
                print(f"  Hash: {result.get('hash', 'N/A')}")
                if result.get('matches_original') is not None:
                    status = '✓ Matches' if result['matches_original'] else '✗ Mismatch'
                    print(f"  Matches Original: {status}")
            
            elif choice == '2':
                backup1 = input("Enter first backup file: ")
                backup2 = input("Enter second backup file: ")
                result = self.backup_verification.compare_backups(backup1, backup2)
                status = f"{Fore.GREEN}IDENTICAL{Style.RESET_ALL}" if result['identical'] else f"{Fore.RED}DIFFERENT{Style.RESET_ALL}"
                print(f"\nBackups are: {status}")
                print(f"  Backup 1 Hash: {result.get('backup1_hash', 'N/A')}")
                print(f"  Backup 2 Hash: {result.get('backup2_hash', 'N/A')}")
            
            elif choice == '3':
                directory = input("Enter directory path: ")
                output_file = input("Enter manifest output file (optional): ") or None
                manifest = self.backup_verification.create_backup_manifest(directory, output_file)
                print(f"\n{Fore.GREEN}Manifest Created:{Style.RESET_ALL}")
                print(f"  Total Files: {manifest['total_files']}")
                print(f"  Total Size: {manifest['total_size']:,} bytes")
                if manifest.get('manifest_file'):
                    print(f"  Saved to: {manifest['manifest_file']}")
            
            elif choice == '4':
                directory = input("Enter directory path: ")
                manifest_file = input("Enter manifest file path: ")
                result = self.backup_verification.verify_backup_against_manifest(directory, manifest_file)
                print(f"\n{Fore.CYAN}Manifest Verification:{Style.RESET_ALL}")
                print(f"  Verified: {'✓' if result['verified'] else '✗'}")
                print(f"  Matches: {result['matches']}")
                print(f"  Mismatches: {result['mismatches']}")
                if result.get('missing_files'):
                    print(f"  Missing Files: {len(result['missing_files'])}")
                if result.get('extra_files'):
                    print(f"  Extra Files: {len(result['extra_files'])}")
            
            elif choice == '5':
                backup_file = input("Enter backup file path: ")
                result = self.backup_verification.check_backup_age(backup_file)
                print(f"\n{Fore.CYAN}Backup Age:{Style.RESET_ALL}")
                print(f"  Age: {result.get('age_days', 'N/A')} days")
                print(f"  Last Modified: {result.get('last_modified', 'N/A')}")
                print(f"  Fresh: {'✓' if result.get('is_fresh') else '✗'}")
                if result.get('recommendation'):
                    print(f"  Recommendation: {result['recommendation']}")
            
            elif choice == '6':
                backup_file = input("Enter backup file path: ")
                original_hash = input("Enter original hash (optional): ") or None
                report = self.backup_verification.generate_backup_report(backup_file, original_hash)
                print(report)
            
            elif choice == '7':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def config_security_menu(self):
        """Security configuration checker submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Security Configuration Checker ---{Style.RESET_ALL}")
            print("1. Check Password Policy")
            print("2. Check File Permissions")
            print("3. Check Directory Permissions")
            print("4. Check Environment Variables")
            print("5. Check File Extensions")
            print("6. Check SSH Config")
            print("7. Generate Security Config Report")
            print("8. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                result = self.config_security.check_password_policy()
                print(f"\n{Fore.CYAN}Password Policy Check:{Style.RESET_ALL}")
                for key, value in result.get('checks', {}).items():
                    print(f"  {key}: {value}")
                for rec in result.get('recommendations', []):
                    print(f"  → {rec}")
            
            elif choice == '2':
                file_path = input("Enter file path: ")
                result = self.config_security.check_file_permissions(file_path)
                print(f"\n{Fore.CYAN}File Permissions:{Style.RESET_ALL}")
                print(f"  Permissions: {result.get('permissions', 'N/A')}")
                print(f"  Secure: {'✓' if result.get('secure') else '✗'}")
                if result.get('warnings'):
                    for warning in result['warnings']:
                        print(f"  ⚠ {warning}")
            
            elif choice == '3':
                directory = input("Enter directory path: ")
                result = self.config_security.check_directory_permissions(directory)
                print(f"\n{Fore.CYAN}Directory Permissions:{Style.RESET_ALL}")
                print(f"  Permissions: {result.get('permissions', 'N/A')}")
                print(f"  Secure: {'✓' if result.get('secure') else '✗'}")
                if result.get('files_with_issues'):
                    print(f"  Files with Issues: {len(result['files_with_issues'])}")
            
            elif choice == '4':
                result = self.config_security.check_environment_variables()
                print(f"\n{Fore.CYAN}Environment Variables:{Style.RESET_ALL}")
                print(f"  Sensitive Variables Found: {len(result.get('sensitive_vars_found', []))}")
                if result.get('warnings'):
                    for warning in result['warnings']:
                        print(f"  ⚠ {warning}")
                for rec in result.get('recommendations', []):
                    print(f"  → {rec}")
            
            elif choice == '5':
                directory = input("Enter directory path: ")
                result = self.config_security.check_file_extensions(directory)
                print(f"\n{Fore.CYAN}File Extensions Check:{Style.RESET_ALL}")
                if result.get('dangerous_files'):
                    print(f"  Dangerous Files Found: {len(result['dangerous_files'])}")
                    for file_info in result['dangerous_files'][:10]:
                        print(f"    {file_info['file']} ({file_info['extension']})")
            
            elif choice == '6':
                config_file = input("Enter SSH config file path (optional): ") or None
                result = self.config_security.check_ssh_config(config_file)
                print(f"\n{Fore.CYAN}SSH Config Check:{Style.RESET_ALL}")
                print(f"  Config File: {result.get('config_file', 'N/A')}")
                print(f"  Exists: {'✓' if result.get('exists') else '✗'}")
                print(f"  Secure: {'✓' if result.get('secure') else '✗'}")
                for rec in result.get('recommendations', []):
                    print(f"  → {rec}")
            
            elif choice == '7':
                directory = input("Enter directory to analyze (optional): ") or None
                report = self.config_security.generate_security_config_report(directory)
                print(report)
            
            elif choice == '8':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def phishing_detector_menu(self):
        """Phishing detector submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Phishing & Malicious URL Detection ---{Style.RESET_ALL}")
            print("1. Detect Phishing URL")
            print("2. Batch URL Detection")
            print("3. Generate Phishing Report")
            print("4. Check URL Against Blacklist")
            print("5. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                url = input("Enter URL to analyze: ")
                deep = input("Perform deep analysis? (yes/no, default yes): ").lower() == 'yes' or True
                result = self.phishing_detector.detect_phishing(url, deep_analysis=deep)
                print(f"\n{Fore.CYAN}Phishing Detection Results:{Style.RESET_ALL}")
                print(f"  URL: {result['url']}")
                print(f"  Is Phishing: {'⚠ YES' if result['is_phishing'] else '✓ NO'}")
                print(f"  Confidence: {result['confidence']:.1f}%")
                print(f"  Risk Level: {result['risk_level'].upper()}")
                if result.get('scores'):
                    print(f"\n  Score Breakdown:")
                    for score_type, score_value in result['scores'].items():
                        print(f"    {score_type}: {score_value:.1f}")
                if result.get('indicators'):
                    print(f"\n  Indicators:")
                    for indicator in result['indicators']:
                        print(f"    ⚠ {indicator}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '2':
                urls_input = input("Enter URLs (comma-separated): ")
                urls = [url.strip() for url in urls_input.split(',')]
                results = self.phishing_detector.batch_detect(urls)
                print(f"\n{Fore.CYAN}Batch Detection Results:{Style.RESET_ALL}")
                for url, result in results.items():
                    status = '⚠ PHISHING' if result['is_phishing'] else '✓ Safe'
                    print(f"  {url}: {status} ({result['confidence']:.1f}%)")
            
            elif choice == '3':
                url = input("Enter URL to analyze: ")
                report = self.phishing_detector.generate_phishing_report(url)
                print(report)
            
            elif choice == '4':
                url = input("Enter URL to check: ")
                blacklist_file = input("Enter blacklist file path (optional): ") or None
                in_blacklist = self.phishing_detector.check_url_against_blacklist(url, blacklist_file)
                status = f"{Fore.RED}BLACKLISTED{Style.RESET_ALL}" if in_blacklist else f"{Fore.GREEN}Not in blacklist{Style.RESET_ALL}"
                print(f"\nURL Status: {status}")
            
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def ids_menu(self):
        """Intrusion Detection System submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Intrusion Detection System (IDS) ---{Style.RESET_ALL}")
            print("1. Analyze Log Entry")
            print("2. Detect Port Scan")
            print("3. Detect Brute Force")
            print("4. Detect Anomalous Traffic")
            print("5. Monitor File Changes")
            print("6. View Recent Alerts")
            print("7. Generate IDS Report")
            print("8. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                log_entry = input("Enter log entry to analyze: ")
                source_ip = input("Enter source IP (optional): ") or None
                result = self.ids.analyze_log_entry(log_entry, source_ip)
                print(f"\n{Fore.CYAN}Log Analysis:{Style.RESET_ALL}")
                print(f"  Suspicious: {'⚠ YES' if result['suspicious'] else '✓ NO'}")
                print(f"  Confidence: {result['confidence']:.1f}%")
                if result.get('threat_types'):
                    print(f"  Threat Types: {', '.join(result['threat_types'])}")
                if result.get('recommended_action'):
                    print(f"  Recommended Action: {result['recommended_action']}")
            
            elif choice == '2':
                print(f"{Fore.CYAN}Enter port attempts (format: ip:port, one per line, empty line to finish):{Style.RESET_ALL}")
                attempts = []
                while True:
                    entry = input()
                    if not entry:
                        break
                    try:
                        ip, port = entry.split(':')
                        attempts.append((ip.strip(), int(port.strip())))
                    except:
                        print(f"{Fore.RED}Invalid format. Use ip:port{Style.RESET_ALL}")
                
                if attempts:
                    result = self.ids.detect_port_scan(attempts)
                    if result['port_scan_detected']:
                        print(f"\n{Fore.RED}PORT SCAN DETECTED!{Style.RESET_ALL}")
                        for ip_info in result['suspicious_ips']:
                            print(f"  IP: {ip_info['ip']} - {ip_info['ports_scanned']} ports ({ip_info['severity']})")
                    else:
                        print(f"\n{Fore.GREEN}No port scan detected{Style.RESET_ALL}")
            
            elif choice == '3':
                print(f"{Fore.CYAN}Note: This is a simplified demo. In production, use log files.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Brute force detection requires log file analysis{Style.RESET_ALL}")
                print(f"Use Security Audit tool (option 11) for log-based brute force detection")
            
            elif choice == '4':
                print(f"{Fore.CYAN}Note: Anomalous traffic detection requires traffic data.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}This feature works with network monitoring data{Style.RESET_ALL}")
            
            elif choice == '5':
                file_path = input("Enter file path to monitor: ")
                baseline_hash = input("Enter baseline hash (optional): ") or None
                result = self.ids.monitor_file_changes(file_path, baseline_hash)
                print(f"\n{Fore.CYAN}File Monitoring:{Style.RESET_ALL}")
                print(f"  Modified: {'Yes' if result.get('modified') else 'No'}")
                print(f"  Integrity: {result.get('integrity', 'unknown')}")
                if result.get('change_detected'):
                    print(f"  {Fore.RED}CHANGE DETECTED!{Style.RESET_ALL}")
            
            elif choice == '6':
                hours = int(input("Hours to look back (default 24): ") or "24")
                alerts = self.ids.get_recent_alerts(hours)
                print(f"\n{Fore.CYAN}Recent Alerts ({len(alerts)}):{Style.RESET_ALL}")
                for alert in alerts[:20]:
                    print(f"  {alert['timestamp']} - {alert['event_type']} ({alert['severity']})")
            
            elif choice == '7':
                log_file = input("Enter log file path (optional): ") or None
                report = self.ids.generate_ids_report(log_file)
                print(report)
            
            elif choice == '8':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def malware_detector_menu(self):
        """Malware detector submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Malware Detection (ML) ---{Style.RESET_ALL}")
            print("1. Detect Malware in File")
            print("2. Scan Directory")
            print("3. Generate Malware Report")
            print("4. Batch File Detection")
            print("5. Load Malware Database")
            print("6. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                file_path = input("Enter file path to analyze: ")
                use_ml = input("Use ML detection? (yes/no, default yes): ").lower() != 'no'
                result = self.malware_detector.detect_malware(file_path, use_ml=use_ml)
                print(f"\n{Fore.CYAN}Malware Detection Results:{Style.RESET_ALL}")
                print(f"  File: {result['file_path']}")
                print(f"  Is Malware: {'⚠ YES' if result['is_malware'] else '✓ NO'}")
                print(f"  Confidence: {result['confidence']:.1f}%")
                print(f"  Risk Level: {result['risk_level'].upper()}")
                print(f"  Detection Method: {result['detection_method']}")
                if result.get('indicators'):
                    print(f"\n  Indicators:")
                    for indicator in result['indicators']:
                        print(f"    ⚠ {indicator}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '2':
                directory = input("Enter directory path to scan: ")
                recursive = input("Scan recursively? (yes/no, default yes): ").lower() != 'no'
                print(f"\n{Fore.CYAN}Scanning directory...{Style.RESET_ALL}")
                results = self.malware_detector.scan_directory(directory, recursive)
                
                malware_files = [path for path, res in results.items() if res.get('is_malware')]
                safe_files = [path for path, res in results.items() if not res.get('is_malware') and 'error' not in res]
                
                print(f"\n{Fore.CYAN}Scan Results:{Style.RESET_ALL}")
                print(f"  Total Files: {len(results)}")
                print(f"  Malware Detected: {len(malware_files)}")
                print(f"  Safe Files: {len(safe_files)}")
                
                if malware_files:
                    print(f"\n  {Fore.RED}Malware Files:{Style.RESET_ALL}")
                    for file_path in malware_files[:10]:  # Show first 10
                        print(f"    ⚠ {file_path}")
            
            elif choice == '3':
                file_path = input("Enter file path to analyze: ")
                report = self.malware_detector.generate_malware_report(file_path)
                print(report)
            
            elif choice == '4':
                files_input = input("Enter file paths (comma-separated): ")
                file_paths = [f.strip() for f in files_input.split(',')]
                results = self.malware_detector.batch_detect(file_paths)
                print(f"\n{Fore.CYAN}Batch Detection Results:{Style.RESET_ALL}")
                for file_path, result in results.items():
                    status = '⚠ MALWARE' if result.get('is_malware') else '✓ Safe'
                    print(f"  {file_path}: {status} ({result.get('confidence', 0):.1f}%)")
            
            elif choice == '5':
                database_file = input("Enter malware database file path: ")
                self.malware_detector.load_malware_database(database_file)
                print(f"{Fore.GREEN}Malware database loaded{Style.RESET_ALL}")
            
            elif choice == '6':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def email_spam_detector_menu(self):
        """Email spam & phishing detector submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Email Spam & Phishing Detection ---{Style.RESET_ALL}")
            print("1. Analyze Email")
            print("2. Batch Analyze Emails")
            print("3. Generate Detection Report")
            print("4. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                print(f"{Fore.CYAN}Paste email content (headers + body), then press Enter twice:{Style.RESET_ALL}")
                lines = []
                while True:
                    line = input()
                    if line == "" and lines and lines[-1] == "":
                        break
                    lines.append(line)
                email_content = "\n".join(lines)
                result = self.email_spam_detector.analyze_email(email_content)
                print(f"\n{Fore.CYAN}Analysis Results:{Style.RESET_ALL}")
                print(f"  Spam: {'⚠ YES' if result['is_spam'] else '✓ NO'} (Score: {result['spam_score']:.1f}%)")
                print(f"  Phishing: {'⚠ YES' if result['is_phishing'] else '✓ NO'} (Score: {result['phishing_score']:.1f}%)")
                print(f"  Overall Risk: {result['overall_risk'].upper()}")
                if result.get('indicators'):
                    print(f"\n  Indicators:")
                    for indicator in result['indicators'][:10]:
                        print(f"    ⚠ {indicator}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '2':
                print(f"{Fore.YELLOW}Batch analysis requires email file input{Style.RESET_ALL}")
                print(f"Use individual email analysis (option 1) for multiple emails")
            
            elif choice == '3':
                print(f"{Fore.CYAN}Paste email content, then press Enter twice:{Style.RESET_ALL}")
                lines = []
                while True:
                    line = input()
                    if line == "" and lines and lines[-1] == "":
                        break
                    lines.append(line)
                email_content = "\n".join(lines)
                report = self.email_spam_detector.generate_report(email_content)
                print(report)
            
            elif choice == '4':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def keylogger_detector_menu(self):
        """Keylogger detector submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Keylogger Detection ---{Style.RESET_ALL}")
            print("1. Scan for Keylogger Processes")
            print("2. Check Startup Programs")
            print("3. Full System Scan")
            print("4. Generate Detection Report")
            print("5. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                result = self.keylogger_detector.detect_keylogger_processes()
                print(f"\n{Fore.CYAN}Process Scan Results:{Style.RESET_ALL}")
                print(f"  Keyloggers Detected: {'⚠ YES' if result['keyloggers_detected'] else '✓ NO'}")
                print(f"  Processes Checked: {result['total_processes_checked']}")
                if result.get('suspicious_processes'):
                    print(f"\n  Suspicious Processes:")
                    for proc in result['suspicious_processes'][:10]:
                        print(f"    ⚠ {proc['name']} (PID: {proc['pid']}) - {proc['reason']}")
                if result.get('recommendations'):
                    for rec in result['recommendations']:
                        print(f"  → {rec}")
            
            elif choice == '2':
                result = self.keylogger_detector.check_startup_programs()
                print(f"\n{Fore.CYAN}Startup Programs Check:{Style.RESET_ALL}")
                if result.get('suspicious_startup_programs'):
                    print(f"  Suspicious Programs: {len(result['suspicious_startup_programs'])}")
                    for prog in result['suspicious_startup_programs']:
                        print(f"    ⚠ {prog['file']} - {prog['reason']}")
                else:
                    print(f"  ✓ No suspicious startup programs found")
            
            elif choice == '3':
                print(f"\n{Fore.CYAN}Running full system scan...{Style.RESET_ALL}")
                result = self.keylogger_detector.scan_system()
                print(f"\n  Overall Risk: {result['overall_risk'].upper()}")
                print(f"  Keyloggers Detected: {'⚠ YES' if result['keyloggers_detected'] else '✓ NO'}")
                if result.get('recommendations'):
                    print(f"\n  Recommendations:")
                    for rec in result['recommendations']:
                        print(f"    → {rec}")
            
            elif choice == '4':
                report = self.keylogger_detector.generate_report()
                print(report)
            
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def blockchain_voting_menu(self):
        """Blockchain voting system submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Blockchain Voting System ---{Style.RESET_ALL}")
            print("1. Register Voter")
            print("2. Cast Vote")
            print("3. Mine Block (Process Votes)")
            print("4. View Results")
            print("5. Verify Blockchain")
            print("6. Generate Voting Report")
            print("7. Export Blockchain")
            print("8. Import Blockchain")
            print("9. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                voter_id = input("Enter voter ID: ")
                result = self.voting_system.register_voter(voter_id)
                status = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}" if result['success'] else f"{Fore.RED}FAILED{Style.RESET_ALL}"
                print(f"\nRegistration: {status}")
                print(f"  {result['message']}")
            
            elif choice == '2':
                voter_id = input("Enter voter ID: ")
                candidate = input("Enter candidate/option to vote for: ")
                result = self.voting_system.cast_vote(voter_id, candidate)
                status = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}" if result['success'] else f"{Fore.RED}FAILED{Style.RESET_ALL}"
                print(f"\nVote: {status}")
                print(f"  {result['message']}")
                if result.get('vote_id'):
                    print(f"  Vote ID: {result['vote_id']}")
            
            elif choice == '3':
                print(f"\n{Fore.CYAN}Mining block...{Style.RESET_ALL}")
                result = self.voting_system.mine_block()
                status = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}" if result['success'] else f"{Fore.RED}FAILED{Style.RESET_ALL}"
                print(f"Mining: {status}")
                print(f"  {result['message']}")
                if result.get('block'):
                    print(f"  Block Index: {result['block']['index']}")
                    print(f"  Votes in Block: {len(result['block']['votes'])}")
            
            elif choice == '4':
                results = self.voting_system.get_results()
                print(f"\n{Fore.CYAN}Voting Results:{Style.RESET_ALL}")
                print(f"  Total Votes: {results['total_votes']}")
                print(f"  Blocks: {results['blocks_count']}")
                print(f"\n  Results:")
                for candidate, votes in sorted(results['results'].items(), key=lambda x: x[1], reverse=True):
                    percentage = (votes / results['total_votes'] * 100) if results['total_votes'] > 0 else 0
                    print(f"    {candidate}: {votes} votes ({percentage:.1f}%)")
            
            elif choice == '5':
                verification = self.voting_system.verify_chain()
                status = f"{Fore.GREEN}VALID{Style.RESET_ALL}" if verification['valid'] else f"{Fore.RED}INVALID{Style.RESET_ALL}"
                print(f"\nBlockchain Status: {status}")
                if verification.get('errors'):
                    print(f"  Errors:")
                    for error in verification['errors']:
                        print(f"    ⚠ {error}")
            
            elif choice == '6':
                report = self.voting_system.generate_voting_report()
                print(report)
            
            elif choice == '7':
                filename = input("Enter filename to save blockchain: ")
                self.voting_system.export_blockchain(filename)
                print(f"{Fore.GREEN}Blockchain exported to {filename}{Style.RESET_ALL}")
            
            elif choice == '8':
                filename = input("Enter filename to load blockchain: ")
                self.voting_system.import_blockchain(filename)
                print(f"{Fore.GREEN}Blockchain imported from {filename}{Style.RESET_ALL}")
            
            elif choice == '9':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def evil_twin_detector_menu(self):
        """Evil twin detector submenu"""
        while True:
            print(f"\n{Fore.GREEN}--- Evil Twin / Fake Wi-Fi Detection ---{Style.RESET_ALL}")
            print("1. Scan Wi-Fi Networks")
            print("2. Detect Evil Twin for SSID")
            print("3. Add Legitimate Network")
            print("4. Generate Network Report")
            print("5. Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}")
            
            if choice == '1':
                print(f"\n{Fore.CYAN}Scanning Wi-Fi networks...{Style.RESET_ALL}")
                result = self.evil_twin_detector.scan_wifi_networks()
                print(f"\n  Networks Found: {result['total_networks']}")
                print(f"  Suspicious Networks: {len(result.get('suspicious_networks', []))}")
                if result.get('suspicious_networks'):
                    print(f"\n  ⚠ Suspicious Networks:")
                    for suspicious in result['suspicious_networks'][:5]:
                        print(f"    {suspicious['type']}: {suspicious.get('ssid', 'N/A')} - {suspicious['reason']}")
                if result.get('error'):
                    print(f"  Error: {result['error']}")
                    print(f"  Note: Wi-Fi scanning may require administrator privileges")
            
            elif choice == '2':
                ssid = input("Enter SSID to check for evil twin: ")
                result = self.evil_twin_detector.detect_evil_twin(ssid)
                print(f"\n{Fore.CYAN}Evil Twin Detection:{Style.RESET_ALL}")
                status = f"{Fore.RED}DETECTED{Style.RESET_ALL}" if result['evil_twin_detected'] else f"{Fore.GREEN}Not Detected{Style.RESET_ALL}"
                print(f"  Evil Twin: {status}")
                if result.get('suspicious_networks'):
                    print(f"  Suspicious Networks: {len(result['suspicious_networks'])}")
                    for network in result['suspicious_networks']:
                        print(f"    SSID: {network.get('ssid')}, BSSID: {network.get('bssid', 'N/A')}")
                if result.get('recommendations'):
                    for rec in result['recommendations']:
                        print(f"  → {rec}")
            
            elif choice == '3':
                ssid = input("Enter legitimate network SSID: ")
                self.evil_twin_detector.add_legitimate_network(ssid)
                print(f"{Fore.GREEN}Legitimate network added{Style.RESET_ALL}")
            
            elif choice == '4':
                report = self.evil_twin_detector.generate_network_report()
                print(report)
            
            elif choice == '5':
                break
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
    
    def run(self):
        """Main application loop"""
        while True:
            self.display_menu()
            choice = input(f"{Fore.YELLOW}Select option (1-22): {Style.RESET_ALL}")
            
            if choice == '1':
                self.password_menu()
            elif choice == '2':
                self.encryption_menu()
            elif choice == '3':
                self.network_menu()
            elif choice == '4':
                self.utilities_menu()
            elif choice == '5':
                self.privacy_menu()
            elif choice == '6':
                self.two_factor_menu()
            elif choice == '7':
                self.secure_deletion_menu()
            elif choice == '8':
                self.url_security_menu()
            elif choice == '9':
                self.email_security_menu()
            elif choice == '10':
                self.security_headers_menu()
            elif choice == '11':
                self.security_audit_menu()
            elif choice == '12':
                self.certificate_analyzer_menu()
            elif choice == '13':
                self.backup_verification_menu()
            elif choice == '14':
                self.config_security_menu()
            elif choice == '15':
                self.phishing_detector_menu()
            elif choice == '16':
                self.ids_menu()
            elif choice == '17':
                self.malware_detector_menu()
            elif choice == '18':
                self.email_spam_detector_menu()
            elif choice == '19':
                self.keylogger_detector_menu()
            elif choice == '20':
                self.blockchain_voting_menu()
            elif choice == '21':
                self.evil_twin_detector_menu()
            elif choice == '22':
                print(f"\n{Fore.GREEN}Thank you for using Cybersecurity Solutions Toolkit!{Style.RESET_ALL}")
                sys.exit(0)
            else:
                print(f"{Fore.RED}Invalid option. Please select 1-22.{Style.RESET_ALL}")


if __name__ == "__main__":
    toolkit = CyberSecurityToolkit()
    toolkit.run()
