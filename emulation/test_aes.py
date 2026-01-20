#!/usr/bin/env python3
"""
Test script comparing Python AES reference with assembly emulation.

Tests with:
- All zeros input
- 30 random inputs
"""

import os
import sys

# Import our modules
from aes_reference import aes_ctr_decrypt
from aes_emulator import AESEmulator, create_4way_key, create_iv_shares


def test_single(emu: AESEmulator, key: bytes, iv: bytes, ciphertext: bytes, 
                test_name: str = "test") -> bool:
    """
    Test a single case comparing Python AES with emulated assembly.
    
    Args:
        emu: AES emulator instance
        key: 32-byte AES-256 key (regular, not 4-way shared)
        iv: 16-byte IV (regular, not shared)
        ciphertext: 16-byte ciphertext
        test_name: Name for this test case
    
    Returns:
        True if test passed, False otherwise
    """
    # Get Python reference result (using regular key/IV)
    py_result = aes_ctr_decrypt(key, iv, ciphertext)
    
    # Convert key to 4-way share format for emulator
    key4way = create_4way_key(key)
    
    # Convert IV to 2-way share format for emulator
    iv_share_a, iv_share_b = create_iv_shares(iv)
    
    # Get emulated assembly result
    asm_result = emu.decrypt(key4way, iv_share_a, iv_share_b, ciphertext, num_blocks=1)
    
    # Compare
    if py_result == asm_result:
        print(f"[PASS] {test_name}")
        return True
    else:
        print(f"[FAIL] {test_name}")
        print(f"  Key: {key.hex()}")
        print(f"  IV: {iv.hex()}")
        print(f"  Ciphertext: {ciphertext.hex()}")
        print(f"  Python result: {py_result.hex()}")
        print(f"  ASM result: {asm_result.hex()}")
        return False


def test_all_zeros():
    """Test with all zeros input"""
    print("\n=== Testing All Zeros ===")
    
    emu = AESEmulator(debug=False)
    
    key = b'\x00' * 32
    iv = b'\x00' * 16
    ciphertext = b'\x00' * 16
    
    return test_single(emu, key, iv, ciphertext, "all_zeros")


def test_random_inputs(num_tests: int = 30):
    """Test with random inputs"""
    print(f"\n=== Testing {num_tests} Random Inputs ===")
    
    emu = AESEmulator(debug=False)
    
    passed = 0
    failed = 0
    
    for i in range(num_tests):
        # Generate random key, IV, and ciphertext
        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = os.urandom(16)
        
        if test_single(emu, key, iv, ciphertext, f"random_{i+1:02d}"):
            passed += 1
        else:
            failed += 1
    
    print(f"\nRandom tests: {passed}/{num_tests} passed, {failed} failed")
    return failed == 0


def test_known_vectors():
    """Test with known test vectors"""
    print("\n=== Testing Known Vectors ===")
    
    emu = AESEmulator(debug=False)
    
    # Test vector 1: Specific key and IV
    key = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    iv = bytes.fromhex('00000000000000000000000000000000')
    ciphertext = bytes.fromhex('00000000000000000000000000000000')
    
    result1 = test_single(emu, key, iv, ciphertext, "known_vector_1")
    
    # Test vector 2: Another pattern
    key = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    iv = bytes.fromhex('ffffffffffffffffffffffffffffffff')
    ciphertext = bytes.fromhex('00000000000000000000000000000000')
    
    result2 = test_single(emu, key, iv, ciphertext, "known_vector_2")
    
    # Test vector 3: Sequential bytes
    key = bytes(range(32))
    iv = bytes(range(16))
    ciphertext = bytes(range(16))
    
    result3 = test_single(emu, key, iv, ciphertext, "known_vector_3")
    
    return result1 and result2 and result3


def main():
    """Run all tests"""
    print("=" * 60)
    print("AES-256 CTR Mode: Python Reference vs Assembly Emulation")
    print("=" * 60)
    
    all_passed = True
    
    # Test with all zeros
    if not test_all_zeros():
        all_passed = False
    
    # Test with known vectors
    if not test_known_vectors():
        all_passed = False
    
    # Test with random inputs
    if not test_random_inputs(30):
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED!")
        sys.exit(1)
    print("=" * 60)


if __name__ == '__main__':
    main()
