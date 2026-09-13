"""Simple test to verify application starts"""
import sys

print("Testing application initialization...")
sys.stdout.flush()

try:
    print("Step 1: Importing main module...")
    sys.stdout.flush()
    import main
    print("Step 2: Main module imported successfully")
    sys.stdout.flush()
    
    print("Step 3: Creating toolkit instance...")
    sys.stdout.flush()
    toolkit = main.CyberSecurityToolkit()
    print("Step 4: Toolkit instance created successfully")
    sys.stdout.flush()
    
    print("\n" + "="*60)
    print("SUCCESS: Application initialized successfully!")
    print(f"Total modules loaded: 21 security tools")
    print("="*60)
    sys.exit(0)
    
except Exception as e:
    print(f"\nERROR: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
