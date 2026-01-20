"""
RP2350 Hardware Peripheral Emulation

Provides emulated versions of:
- TRNG (True Random Number Generator)
- SHA256 Hardware Accelerator
- ROSC (Ring Oscillator)
- RESETS Controller
"""

import struct
import hashlib
import os
from typing import Dict, Optional, Callable
from rp2350_hw import *


class TRNGEmulator:
    """Emulates the RP2350 TRNG (True Random Number Generator)"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.rng_imr = 0x0000000f
        self.rng_isr = 0x00000000
        self.rng_icr = 0x00000000
        self.trng_config = 0x00000000
        self.rnd_source_enable = 0x00000000
        self.sample_cnt1 = 0x0000ffff
        self.debug_control = 0x00000000
        self.sw_reset = 0x00000000
        self.busy = 0x00000000
        # EHR data - 6 words of random data
        self._refresh_ehr_data()
    
    def _refresh_ehr_data(self):
        """Generate new random EHR data"""
        self.ehr_data = [
            int.from_bytes(os.urandom(4), 'little') for _ in range(6)
        ]
    
    def read(self, offset: int) -> int:
        """Read from TRNG register"""
        if offset == TRNG_RNG_IMR_OFFSET:
            return self.rng_imr
        elif offset == TRNG_RNG_ISR_OFFSET:
            return self.rng_isr
        elif offset == TRNG_RNG_ICR_OFFSET:
            return self.rng_icr
        elif offset == TRNG_TRNG_CONFIG_OFFSET:
            return self.trng_config
        elif offset == TRNG_TRNG_VALID_OFFSET:
            return 1  # Always valid for emulation
        elif offset == TRNG_EHR_DATA0_OFFSET:
            return self.ehr_data[0]
        elif offset == TRNG_EHR_DATA1_OFFSET:
            return self.ehr_data[1]
        elif offset == TRNG_EHR_DATA2_OFFSET:
            return self.ehr_data[2]
        elif offset == TRNG_EHR_DATA3_OFFSET:
            return self.ehr_data[3]
        elif offset == TRNG_EHR_DATA4_OFFSET:
            return self.ehr_data[4]
        elif offset == TRNG_EHR_DATA5_OFFSET:
            return self.ehr_data[5]
        elif offset == TRNG_RND_SOURCE_ENABLE_OFFSET:
            return self.rnd_source_enable
        elif offset == TRNG_SAMPLE_CNT1_OFFSET:
            return self.sample_cnt1
        elif offset == TRNG_TRNG_DEBUG_CONTROL_OFFSET:
            return self.debug_control
        elif offset == TRNG_TRNG_SW_RESET_OFFSET:
            return 0  # Reading SW_RESET returns 0
        elif offset == TRNG_TRNG_BUSY_OFFSET:
            return 0  # Never busy in emulation
        else:
            return 0
    
    def write(self, offset: int, value: int):
        """Write to TRNG register"""
        if offset == TRNG_RNG_IMR_OFFSET:
            self.rng_imr = value
        elif offset == TRNG_RNG_ICR_OFFSET:
            # Writing clears corresponding ISR bits
            self.rng_icr = value
            self.rng_isr &= ~value
            # Refresh EHR data when ICR is written (clearing EHR_VALID triggers new collection)
            if value & 0x1:
                self._refresh_ehr_data()
        elif offset == TRNG_TRNG_CONFIG_OFFSET:
            self.trng_config = value
        elif offset == TRNG_RND_SOURCE_ENABLE_OFFSET:
            self.rnd_source_enable = value
            if value & 1:
                # Starting random source - generate new data
                self._refresh_ehr_data()
        elif offset == TRNG_SAMPLE_CNT1_OFFSET:
            self.sample_cnt1 = value
        elif offset == TRNG_TRNG_DEBUG_CONTROL_OFFSET:
            self.debug_control = value
        elif offset == TRNG_TRNG_SW_RESET_OFFSET:
            if value & 1:
                self.reset()


class SHA256Emulator:
    """Emulates the RP2350 SHA256 Hardware Accelerator"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.csr = SHA256_CSR_RESET
        self.wdata_buffer = []
        # Initialize with SHA256 initial hash values
        self._init_hash_state()
    
    def _init_hash_state(self):
        """Initialize SHA256 hash state with standard IV"""
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
    
    def _process_block(self):
        """Process a 512-bit (16 word) block through SHA256"""
        if len(self.wdata_buffer) < 16:
            return
        
        # Get the 16 words for this block
        block_words = self.wdata_buffer[:16]
        self.wdata_buffer = self.wdata_buffer[16:]
        
        # Check if byte swapping is enabled
        bswap = (self.csr & SHA256_CSR_BSWAP_BITS) != 0
        
        # Convert words to bytes
        block_bytes = b''
        for w in block_words:
            if bswap:
                # Byte swap each word
                block_bytes += struct.pack('>I', w)
            else:
                block_bytes += struct.pack('<I', w)
        
        # Use Python's hashlib for the actual SHA256 computation
        # We'll do incremental hashing by using the internal state
        # For simplicity, we'll just hash the current state + block
        
        # Actually, the hardware does proper SHA256 block processing
        # Let's implement proper SHA256 compression
        self._sha256_compress(block_bytes)
        
        # Set SUM_VLD
        self.csr |= SHA256_CSR_SUM_VLD_BITS
    
    def _sha256_compress(self, block: bytes):
        """SHA256 compression function for a single 512-bit block"""
        # SHA256 constants
        K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ]
        
        def rotr(x, n):
            return ((x >> n) | (x << (32 - n))) & 0xffffffff
        
        def ch(x, y, z):
            return (x & y) ^ (~x & z)
        
        def maj(x, y, z):
            return (x & y) ^ (x & z) ^ (y & z)
        
        def sigma0(x):
            return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
        
        def sigma1(x):
            return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
        
        def gamma0(x):
            return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
        
        def gamma1(x):
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
        
        # Parse block into 16 32-bit words (big-endian)
        W = list(struct.unpack('>16I', block))
        
        # Extend to 64 words
        for i in range(16, 64):
            W.append((gamma1(W[i-2]) + W[i-7] + gamma0(W[i-15]) + W[i-16]) & 0xffffffff)
        
        # Initialize working variables
        a, b, c, d, e, f, g, h = self.h
        
        # Main loop
        for i in range(64):
            T1 = (h + sigma1(e) + ch(e, f, g) + K[i] + W[i]) & 0xffffffff
            T2 = (sigma0(a) + maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + T1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xffffffff
        
        # Add compressed chunk to current hash value
        self.h[0] = (self.h[0] + a) & 0xffffffff
        self.h[1] = (self.h[1] + b) & 0xffffffff
        self.h[2] = (self.h[2] + c) & 0xffffffff
        self.h[3] = (self.h[3] + d) & 0xffffffff
        self.h[4] = (self.h[4] + e) & 0xffffffff
        self.h[5] = (self.h[5] + f) & 0xffffffff
        self.h[6] = (self.h[6] + g) & 0xffffffff
        self.h[7] = (self.h[7] + h) & 0xffffffff
    
    def read(self, offset: int) -> int:
        """Read from SHA256 register"""
        if offset == SHA256_CSR_OFFSET:
            return self.csr
        elif offset == SHA256_WDATA_OFFSET:
            return 0  # WDATA is write-only
        elif offset == SHA256_SUM0_OFFSET:
            return self.h[0]
        elif offset == SHA256_SUM1_OFFSET:
            return self.h[1]
        elif offset == SHA256_SUM2_OFFSET:
            return self.h[2]
        elif offset == SHA256_SUM3_OFFSET:
            return self.h[3]
        elif offset == SHA256_SUM4_OFFSET:
            return self.h[4]
        elif offset == SHA256_SUM5_OFFSET:
            return self.h[5]
        elif offset == SHA256_SUM6_OFFSET:
            return self.h[6]
        elif offset == SHA256_SUM7_OFFSET:
            return self.h[7]
        else:
            return 0
    
    def write(self, offset: int, value: int):
        """Write to SHA256 register"""
        if offset == SHA256_CSR_OFFSET:
            # Handle START bit
            if value & SHA256_CSR_START_BITS:
                self._init_hash_state()
                self.wdata_buffer = []
                self.csr = (value & ~SHA256_CSR_START_BITS) | SHA256_CSR_WDATA_RDY_BITS | SHA256_CSR_SUM_VLD_BITS
            else:
                # Only update BSWAP and DMA_SIZE
                self.csr = (self.csr & ~0x1300) | (value & 0x1300)
        elif offset == SHA256_WDATA_OFFSET:
            self.wdata_buffer.append(value)
            # Clear SUM_VLD when writing data
            self.csr &= ~SHA256_CSR_SUM_VLD_BITS
            # Process block when we have 16 words
            if len(self.wdata_buffer) >= 16:
                self._process_block()


class ROSCEmulator:
    """Emulates the RP2350 ROSC (Ring Oscillator)"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.ctrl = 0x00000aa0
        self.freqa = 0x00000000
        self.freqb = 0x00000000
        self.random = 0x3f04b16d  # Default LFSR seed
        self.dormant = 0x77616b65  # WAKE
        self.div = 0xaa20  # Default div=32
        self.phase = 0x00000008
        self.status = 0x80001000  # STABLE | ENABLED
    
    def read(self, offset: int) -> int:
        """Read from ROSC register"""
        if offset == ROSC_CTRL_OFFSET:
            return self.ctrl
        elif offset == ROSC_FREQA_OFFSET:
            return self.freqa
        elif offset == ROSC_FREQB_OFFSET:
            return self.freqb
        elif offset == ROSC_RANDOM_OFFSET:
            return self.random
        elif offset == ROSC_DORMANT_OFFSET:
            return self.dormant
        elif offset == ROSC_DIV_OFFSET:
            return self.div
        elif offset == ROSC_PHASE_OFFSET:
            return self.phase
        elif offset == ROSC_STATUS_OFFSET:
            return self.status
        elif offset == ROSC_RANDOMBIT_OFFSET:
            # Return a random bit
            return int.from_bytes(os.urandom(1), 'little') & 1
        elif offset == ROSC_COUNT_OFFSET:
            return 0  # Counter has counted down
        else:
            return 0
    
    def write(self, offset: int, value: int):
        """Write to ROSC register"""
        if offset == ROSC_CTRL_OFFSET:
            self.ctrl = value
        elif offset == ROSC_FREQA_OFFSET:
            self.freqa = value
        elif offset == ROSC_FREQB_OFFSET:
            self.freqb = value
        elif offset == ROSC_RANDOM_OFFSET:
            self.random = value
        elif offset == ROSC_DORMANT_OFFSET:
            self.dormant = value
        elif offset == ROSC_DIV_OFFSET:
            self.div = value
        elif offset == ROSC_PHASE_OFFSET:
            self.phase = value


class ResetsEmulator:
    """Emulates the RP2350 RESETS controller"""
    
    def __init__(self, trng: TRNGEmulator, sha256: SHA256Emulator):
        self.trng = trng
        self.sha256 = sha256
        self.reset_reg = 0xffffffff  # All peripherals in reset initially
    
    def read(self, offset: int) -> int:
        """Read from RESETS register"""
        if offset == RESETS_RESET_OFFSET:
            return self.reset_reg
        else:
            return 0
    
    def write(self, offset: int, value: int):
        """Write to RESETS register"""
        if offset == RESETS_RESET_OFFSET:
            # Check if releasing reset on SHA256
            if (self.reset_reg & RESETS_RESET_SHA256_BITS) and not (value & RESETS_RESET_SHA256_BITS):
                self.sha256.reset()
            # Check if releasing reset on TRNG
            if (self.reset_reg & RESETS_RESET_TRNG_BITS) and not (value & RESETS_RESET_TRNG_BITS):
                self.trng.reset()
            self.reset_reg = value


class RP2350HardwareEmulator:
    """Combined hardware emulator for all RP2350 peripherals"""
    
    def __init__(self):
        self.trng = TRNGEmulator()
        self.sha256 = SHA256Emulator()
        self.rosc = ROSCEmulator()
        self.resets = ResetsEmulator(self.trng, self.sha256)
    
    def read32(self, address: int) -> int:
        """Read a 32-bit value from a peripheral address"""
        if TRNG_BASE <= address < TRNG_BASE + 0x1000:
            return self.trng.read(address - TRNG_BASE)
        elif SHA256_BASE <= address < SHA256_BASE + 0x1000:
            return self.sha256.read(address - SHA256_BASE)
        elif ROSC_BASE <= address < ROSC_BASE + 0x1000:
            return self.rosc.read(address - ROSC_BASE)
        elif RESETS_BASE <= address < RESETS_BASE + 0x1000:
            return self.resets.read(address - RESETS_BASE)
        else:
            return 0
    
    def write32(self, address: int, value: int):
        """Write a 32-bit value to a peripheral address"""
        if TRNG_BASE <= address < TRNG_BASE + 0x1000:
            self.trng.write(address - TRNG_BASE, value)
        elif SHA256_BASE <= address < SHA256_BASE + 0x1000:
            self.sha256.write(address - SHA256_BASE, value)
        elif ROSC_BASE <= address < ROSC_BASE + 0x1000:
            self.rosc.write(address - ROSC_BASE, value)
        elif RESETS_BASE <= address < RESETS_BASE + 0x1000:
            self.resets.write(address - RESETS_BASE, value)
