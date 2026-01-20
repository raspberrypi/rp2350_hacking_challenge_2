# AES Assembly Emulation

This directory contains a Python-based emulator for the hardened RP2350
AES implementation.

## Files

- `rp2350_hw.py` - RP2350 hardware register definitions
- `hw_emulation.py` - Hardware peripheral emulators (TRNG, SHA256, ROSC, RESETS)
- `build_asm.py` - Build script to compile aes.S for Cortex-M33
- `aes_emulator.py` - Main Unicorn-based AES emulator
- `aes_reference.py` - Python AES-256 CTR reference implementation
- `test_aes.py` - Test script comparing assembly vs Python AES

## Usage

### Build the assembly
```bash
PICO_SDK_PATH=/path/to/pico-sdk python3 build_asm.py
```

### Run tests
```bash
python3 test_aes.py
```

### Use the emulator directly
```python
from aes_emulator import AESEmulator, create_4way_key, create_iv_shares

# Create emulator
emu = AESEmulator()

# Prepare inputs (using regular key/IV)
key = b'\x00' * 32  # 32-byte AES-256 key
iv = b'\x00' * 16   # 16-byte IV
ciphertext = b'\x00' * 16  # Data to decrypt

# Convert to shared format
key4way = create_4way_key(key)
iv_share_a, iv_share_b = create_iv_shares(iv)

# Decrypt
plaintext = emu.decrypt(key4way, iv_share_a, iv_share_b, ciphertext, num_blocks=1)
```

## How it works

The emulator:
1. Compiles `aes.S` using the ARM toolchain with minimal stub headers
2. Loads the binary into Unicorn Engine (ARM Cortex-M33 emulation)
3. Hooks peripheral memory accesses to emulate:
   - **TRNG**: Returns random data via Python's `os.urandom()`
   - **SHA256**: Full SHA-256 hardware accelerator emulation
   - **ROSC**: Ring oscillator random bit emulation
   - **RESETS**: Peripheral reset controller
4. Executes the `decrypt` function and returns the result
