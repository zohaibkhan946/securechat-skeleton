#!/usr/bin/env python3
"""Run all automated tests."""

import subprocess
import sys
import time


def run_test(test_name, script_path):
    """Run a test script."""
    print(f"\n{'=' * 60}")
    print(f"Running: {test_name}")
    print('=' * 60)
    try:
        result = subprocess.run([sys.executable, script_path], 
                              capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"✗ Test timed out: {test_name}")
        return False
    except Exception as e:
        print(f"✗ Error running test: {e}")
        return False


def main():
    print("=" * 60)
    print("Automated Test Suite")
    print("=" * 60)
    print("\nNote: Some tests require server to be running.")
    print("Make sure to start server before running these tests.\n")
    
    tests = [
        ("Invalid Certificate Test", "test_invalid_cert.py"),
    ]
    
    results = []
    for test_name, script_path in tests:
        success = run_test(test_name, script_path)
        results.append((test_name, success))
        time.sleep(1)
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\nNote: Tampering and replay tests require manual intervention.")
    print("See TESTING_GUIDE.md for complete testing instructions.")


if __name__ == "__main__":
    main()
