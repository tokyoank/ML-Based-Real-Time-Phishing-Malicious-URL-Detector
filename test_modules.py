"""
Quick test script for cybersecurity toolkit modules
"""

import sys

def test_imports():
    """Test if all modules can be imported"""
    modules = [
        'password_security',
        'file_encryption',
        'network_security',
        'security_utilities',
        'data_privacy',
        'two_factor_auth',
        'secure_deletion',
        'url_security',
        'email_security',
        'security_headers',
        'security_audit',
        'certificate_analyzer',
        'backup_verification',
        'config_security',
        'phishing_detector',
        'intrusion_detection',
        'malware_detector_ml',
        'email_spam_phishing',
        'keylogger_detector',
        'blockchain_voting',
        'evil_twin_detector',
    ]
    
    failed = []
    success = []
    
    print("Testing module imports...")
    print("=" * 60)
    
    for module_name in modules:
        try:
            __import__(module_name)
            success.append(module_name)
            print(f"[OK] {module_name}")
        except Exception as e:
            failed.append((module_name, str(e)))
            print(f"[FAIL] {module_name}: {str(e)}")
    
    print("=" * 60)
    print(f"\nResults: {len(success)}/{len(modules)} modules imported successfully")
    
    if failed:
        print(f"\nFailed imports: {len(failed)}")
        for module, error in failed:
            print(f"  - {module}: {error}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality of key modules"""
    print("\nTesting basic functionality...")
    print("=" * 60)
    
    try:
        # Test password security
        from password_security import PasswordSecurity
        ps = PasswordSecurity()
        score, strength, feedback = ps.check_strength("TestPassword123!")
        print(f"[OK] Password Security: {strength} ({score}/100)")
        
        # Test security utilities
        from security_utilities import SecurityUtilities
        su = SecurityUtilities()
        hash_val = su.hash_string("test", "sha256")
        print(f"[OK] Security Utilities: Hash generated ({hash_val[:16]}...)")
        
        # Test 2FA
        from two_factor_auth import TwoFactorAuth
        tfa = TwoFactorAuth()
        key = tfa.generate_secret_key()
        print(f"[OK] 2FA: Secret key generated ({key[:16]}...)")
        
        # Test phishing detector
        from phishing_detector import PhishingDetector
        pd = PhishingDetector()
        result = pd.detect_phishing("http://example.com", deep_analysis=False)
        print(f"[OK] Phishing Detector: Risk level = {result['risk_level']}")
        
        # Test blockchain voting
        from blockchain_voting import BlockchainVotingSystem
        vs = BlockchainVotingSystem()
        vs.register_voter("test_voter")
        vote_result = vs.cast_vote("test_voter", "CandidateA")
        print(f"[OK] Blockchain Voting: {vote_result['message']}")
        
        # Test email spam detector
        from email_spam_phishing import EmailSpamPhishingDetector
        email_detector = EmailSpamPhishingDetector()
        print(f"[OK] Email Spam Detector: Module loaded")
        
        # Test keylogger detector
        from keylogger_detector import KeyloggerDetector
        kl_detector = KeyloggerDetector()
        print(f"[OK] Keylogger Detector: Module loaded")
        
        # Test evil twin detector
        from evil_twin_detector import EvilTwinDetector
        et_detector = EvilTwinDetector()
        print(f"[OK] Evil Twin Detector: Module loaded")
        
        print("=" * 60)
        print("\n[OK] All basic functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"\n[FAIL] Functionality test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("CYBERSECURITY TOOLKIT - MODULE TESTS")
    print("=" * 60 + "\n")
    
    # Test imports
    imports_ok = test_imports()
    
    if imports_ok:
        # Test basic functionality
        functionality_ok = test_basic_functionality()
        
        if functionality_ok:
            print("\n" + "=" * 60)
            print("ALL TESTS PASSED! [SUCCESS]")
            print("=" * 60)
            sys.exit(0)
        else:
            print("\n" + "=" * 60)
            print("SOME FUNCTIONALITY TESTS FAILED")
            print("=" * 60)
            sys.exit(1)
    else:
        print("\n" + "=" * 60)
        print("IMPORT TESTS FAILED")
        print("=" * 60)
        sys.exit(1)
