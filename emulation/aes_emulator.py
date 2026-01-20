#!/usr/bin/env python3
"""
AES Assembly Emulator using Unicorn Engine

Emulates the RP2350 AES implementation from aes.S using Unicorn Engine
with hardware peripheral hooks for TRNG, SHA256, ROSC, and RESETS.
"""

import os
import sys
import struct
from typing import Optional, Tuple

try:
    from unicorn import (
        Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
        UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE, UC_MEM_READ,
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED
    )
    from unicorn.arm_const import *
except ImportError:
    print("ERROR: unicorn-engine not installed. Please run: pip install unicorn")
    sys.exit(1)

# Import our modules
from rp2350_hw import *
from hw_emulation import RP2350HardwareEmulator

# Script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Memory map
CODE_BASE = 0x20080000  # SRAM scratch X
CODE_SIZE = 0x2000      # 8KB (code + data combined since binary includes both)
DATA_BASE = 0x20081000  # SRAM scratch Y (workspace) - overlaps with end of CODE region
DATA_SIZE = 0x1000      # 4KB
STACK_TOP = 0x20082000  # End of SRAM

# Input data area (outside scratch RAM for key/IV/data)
INPUT_BASE = 0x20000000  # Main SRAM
INPUT_SIZE = 0x1000      # 4KB for inputs

# Peripheral regions
PERIPH_BASE = 0x40000000
PERIPH_SIZE = 0x01000000  # 16MB peripheral region

# Symbols (from build output)
SYMBOLS = {
    'decrypt': 0x20080070,
    'chaff': 0x20081000,
    'workspace_start': 0x20081000,
}


class AESEmulator:
    """Unicorn-based emulator for the RP2350 AES implementation"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.hw = RP2350HardwareEmulator()
        self.uc: Optional[Uc] = None
        self._load_binary()
    
    def _load_binary(self):
        """Load the compiled binary"""
        bin_path = os.path.join(SCRIPT_DIR, 'aes.bin')
        elf_path = os.path.join(SCRIPT_DIR, 'aes.elf')
        
        if not os.path.exists(bin_path):
            # Try to build
            print("Binary not found, attempting to build...")
            import build_asm
            if not build_asm.build():
                raise RuntimeError("Failed to build aes.S")
        
        with open(bin_path, 'rb') as f:
            self.code = f.read()
        
        # Get symbols from ELF if available
        if os.path.exists(elf_path):
            try:
                import build_asm
                symbols = build_asm.get_all_symbols()
                SYMBOLS.update(symbols)
            except Exception as e:
                if self.debug:
                    print(f"Warning: Could not read symbols: {e}")
    
    def _setup_unicorn(self):
        """Initialize Unicorn engine with memory map and hooks"""
        # Create Unicorn instance for ARM Cortex-M33 (Thumb mode, M-class)
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        
        # Map a small region at address 0 - the code intentionally reads from there
        # to clear registers (ldmia r0, {r4-r11} where r0=0)
        self.uc.mem_map(0, 0x1000)
        
        # Map code+data region (scratch X + Y combined)
        # The binary includes both .text and .scratch_y.aes sections
        self.uc.mem_map(CODE_BASE, CODE_SIZE)
        self.uc.mem_write(CODE_BASE, self.code)
        
        # Map input data region (main SRAM for key, IV, data)
        self.uc.mem_map(INPUT_BASE, INPUT_SIZE)
        
        # Map peripheral region with hooks
        self.uc.mem_map(PERIPH_BASE, PERIPH_SIZE)
        
        # Add memory hooks for peripheral access
        self.uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self._periph_hook,
            begin=PERIPH_BASE,
            end=PERIPH_BASE + PERIPH_SIZE
        )
        
        # Set up stack pointer
        self.uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        
        # Add hook to catch invalid memory access
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            self._invalid_mem_hook
        )
        
        if self.debug:
            # Add instruction hook for debugging
            self.uc.hook_add(UC_HOOK_CODE, self._debug_hook)
    
    def _periph_hook(self, uc: Uc, access: int, address: int, size: int, value: int, user_data):
        """Memory hook for peripheral access"""
        is_write = (access == UC_MEM_WRITE)
        
        if is_write:
            # Handle write to peripheral
            if self.debug:
                print(f"PERIPH WRITE: 0x{address:08x} = 0x{value:08x}")
            self.hw.write32(address, value)
        else:
            # Handle read from peripheral
            result = self.hw.read32(address)
            if self.debug:
                print(f"PERIPH READ: 0x{address:08x} -> 0x{result:08x}")
            # Write result back to memory so the read returns correct value
            uc.mem_write(address, struct.pack('<I', result))
        
        return True
    
    def _invalid_mem_hook(self, uc: Uc, access: int, address: int, size: int, value: int, user_data):
        """Hook for invalid memory access"""
        pc = uc.reg_read(UC_ARM_REG_PC)
        is_write = (access == UC_MEM_WRITE)
        print(f"INVALID MEM {'WRITE' if is_write else 'READ'}: 0x{address:08x} (size={size}) at PC=0x{pc:08x}")
        return False  # Stop emulation
    
    def _debug_hook(self, uc: Uc, address: int, size: int, user_data):
        """Debug hook for tracing execution"""
        # Only print occasionally to avoid too much output
        if address in [SYMBOLS.get('decrypt'), SYMBOLS.get('ctr_crypt_s')]:
            print(f">>> Executing at 0x{address:08x}")
    
    def decrypt(self, key4way: bytes, iv_share_a: bytes, iv_share_b: bytes, 
                ciphertext: bytes, num_blocks: int = 1) -> bytes:
        """
        Run the AES decrypt function
        
        Args:
            key4way: 128-byte 4-way shared key (64 bytes + 64 byte gap for FIB workaround is not used)
            iv_share_a: 16-byte IV share A
            iv_share_b: 16-byte IV share B
            ciphertext: Data to decrypt (16 bytes per block)
            num_blocks: Number of 16-byte blocks
        
        Returns:
            Decrypted plaintext
        """
        # Set up fresh Unicorn instance
        self._setup_unicorn()
        
        # Allocate input regions
        key_addr = INPUT_BASE + 0x000     # Key at offset 0
        iv_a_addr = INPUT_BASE + 0x100    # IV share A at offset 0x100
        iv_b_addr = INPUT_BASE + 0x120    # IV share B at offset 0x120
        data_addr = INPUT_BASE + 0x200    # Data at offset 0x200
        
        # Write input data to memory
        self.uc.mem_write(key_addr, key4way[:128].ljust(128, b'\x00'))
        self.uc.mem_write(iv_a_addr, iv_share_a[:16].ljust(16, b'\x00'))
        self.uc.mem_write(iv_b_addr, iv_share_b[:16].ljust(16, b'\x00'))
        self.uc.mem_write(data_addr, ciphertext[:num_blocks * 16])
        
        # Set up registers for function call
        # r0 = key4way pointer
        # r1 = IV_shareA pointer
        # r2 = IV_shareB pointer  
        # r3 = message buffer pointer
        # [sp] = number of blocks
        self.uc.reg_write(UC_ARM_REG_R0, key_addr)
        self.uc.reg_write(UC_ARM_REG_R1, iv_a_addr)
        self.uc.reg_write(UC_ARM_REG_R2, iv_b_addr)
        self.uc.reg_write(UC_ARM_REG_R3, data_addr)
        
        # Push num_blocks onto stack
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        sp -= 4
        self.uc.mem_write(sp, struct.pack('<I', num_blocks))
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        
        # Set link register to a return address (we'll stop there)
        # Use a valid address in our code region
        return_addr = CODE_BASE + len(self.code) + 0x100  # After code but within mapped region
        self.uc.reg_write(UC_ARM_REG_LR, return_addr | 1)  # +1 for Thumb mode
        
        # Get decrypt function address
        decrypt_addr = SYMBOLS.get('decrypt', 0x20080070)
        
        if self.debug:
            print(f"Calling decrypt at 0x{decrypt_addr:08x}")
            print(f"  r0 (key): 0x{key_addr:08x}")
            print(f"  r1 (iv_a): 0x{iv_a_addr:08x}")
            print(f"  r2 (iv_b): 0x{iv_b_addr:08x}")
            print(f"  r3 (data): 0x{data_addr:08x}")
            print(f"  [sp] (nblk): {num_blocks}")
        
        # Execute
        try:
            # Start address must have +1 for Thumb mode
            self.uc.emu_start(decrypt_addr | 1, return_addr, timeout=0)  # No timeout
        except UcError as e:
            if self.debug:
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                print(f"Unicorn error at PC=0x{pc:08x}: {e}")
            raise
        
        # Read back decrypted data
        plaintext = self.uc.mem_read(data_addr, num_blocks * 16)
        
        return bytes(plaintext)


def create_4way_key(key: bytes) -> bytes:
    """
    Create a 4-way shared key from a 32-byte AES-256 key
    
    Each word K of the key is expanded into four words a, b, c, d such that a ^ b ^ c ^ d = K
    Layout: a0 b0 c0 d0 a1 b1 c1 d1 ... a7 b7 c7 d7 (128 bytes total)
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    
    result = bytearray()
    
    for i in range(0, 32, 4):
        k_word = key[i:i+4]
        # Generate random shares
        a = os.urandom(4)
        b = os.urandom(4)
        c = os.urandom(4)
        # d = K ^ a ^ b ^ c
        d = bytes(k_word[j] ^ a[j] ^ b[j] ^ c[j] for j in range(4))
        result.extend(a)
        result.extend(b)
        result.extend(c)
        result.extend(d)
    
    return bytes(result)


def create_iv_shares(iv: bytes) -> Tuple[bytes, bytes]:
    """
    Create 2-way shared IV from a 16-byte IV
    
    Returns (iv_share_a, iv_share_b) such that iv_share_a ^ iv_share_b = iv
    """
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    
    iv_share_a = os.urandom(16)
    iv_share_b = bytes(iv[i] ^ iv_share_a[i] for i in range(16))
    
    return iv_share_a, iv_share_b


def test_emulator():
    """Test the emulator with a simple example"""
    print("Testing AES Emulator...")
    
    # Create emulator
    emu = AESEmulator(debug=False)
    
    # Test key (all zeros for simplicity)
    key = b'\x00' * 32
    key4way = create_4way_key(key)
    
    # Test IV (all zeros)
    iv = b'\x00' * 16
    iv_a, iv_b = create_iv_shares(iv)
    
    # Test ciphertext (all zeros - this would be the input to decrypt)
    ciphertext = b'\x00' * 16
    
    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    
    # Run decryption
    try:
        plaintext = emu.decrypt(key4way, iv_a, iv_b, ciphertext, num_blocks=1)
        print(f"Plaintext: {plaintext.hex()}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    test_emulator()
