#!/usr/bin/env python3
"""
Build script to compile aes.S for emulation using arm-none-eabi toolchain
"""

import subprocess
import os
import sys

# Get paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PICO_SDK_PATH = os.environ.get('PICO_SDK_PATH', os.path.expanduser('~/code/git/pico-sdk'))

# Output files
OUTPUT_ELF = os.path.join(SCRIPT_DIR, 'aes.elf')
OUTPUT_BIN = os.path.join(SCRIPT_DIR, 'aes.bin')

# Include paths - our stubs first, then SDK
INCLUDE_PATHS = [
    os.path.join(SCRIPT_DIR, 'include'),  # Our stub includes first
    PROJECT_DIR,
    os.path.join(PICO_SDK_PATH, 'src/rp2350/hardware_regs/include'),
]

# Preprocessor definitions (from CMakeLists.txt)
DEFINES = [
    'RC_COUNT=0',
    'HARDENING=0',
    'DOUBLE_HARDENING=0',
    'INLINE_REF_ROUNDKEY_SHARES_S=1',
    'INLINE_REF_ROUNDKEY_HVPERMS_S=1',
    'INLINE_SHIFT_ROWS_S=1',
    'INLINE_MAP_SBOX_S=1',
    'CALLER_INIT_RCP_COUNT=1',
    'RC_CANARY=0',
    'FIB_WORKAROUND=0',
]

# Linker script for standalone emulation
LINKER_SCRIPT = """
MEMORY
{
    /* Code goes in SRAM scratch X */
    CODE (rwx) : ORIGIN = 0x20080000, LENGTH = 4K
    /* Data/workspace in SRAM scratch Y */
    DATA (rw) : ORIGIN = 0x20081000, LENGTH = 4K
    /* Stack at the end */
    STACK (rw) : ORIGIN = 0x20081C00, LENGTH = 1K
}

SECTIONS
{
    .text : {
        *(.text)
        *(.text.*)
    } > CODE

    .data : {
        *(.data)
        *(.data.*)
    } > DATA

    .scratch_y.aes : {
        *(.scratch_y.aes)
    } > DATA

    .bss : {
        *(.bss)
        *(.bss.*)
    } > DATA
    
    /* Provide stack pointer */
    __stack_top = ORIGIN(STACK) + LENGTH(STACK);
}

ENTRY(decrypt)
"""


def create_linker_script():
    """Create linker script file"""
    ld_path = os.path.join(SCRIPT_DIR, 'aes.ld')
    with open(ld_path, 'w') as f:
        f.write(LINKER_SCRIPT)
    return ld_path


def build():
    """Build the assembly file"""
    print("Building aes.S for Cortex-M33...")
    
    # Check for toolchain
    try:
        subprocess.run(['arm-none-eabi-gcc', '--version'], 
                      capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: arm-none-eabi-gcc not found. Please install ARM toolchain.")
        print("On macOS: brew install arm-none-eabi-gcc")
        print("On Ubuntu: sudo apt install gcc-arm-none-eabi")
        return False
    
    # Check include paths exist
    for path in INCLUDE_PATHS:
        if not os.path.exists(path):
            print(f"WARNING: Include path not found: {path}")
    
    # Create linker script
    ld_path = create_linker_script()
    
    # Build command
    cmd = [
        'arm-none-eabi-gcc',
        '-mcpu=cortex-m33',
        '-mthumb',
        '-mfloat-abi=soft',
        '-nostdlib',
        '-nostartfiles',
        '-ffreestanding',
        '-g',  # Debug info
        '-O0',  # No optimization to preserve code structure
    ]
    
    # Add include paths
    for path in INCLUDE_PATHS:
        cmd.extend(['-I', path])
    
    # Add defines
    for define in DEFINES:
        cmd.extend(['-D', define])
    
    # Add source and output
    cmd.extend([
        '-T', ld_path,
        '-o', OUTPUT_ELF,
        os.path.join(PROJECT_DIR, 'aes.S'),
    ])
    
    print(f"Running: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Build failed!")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        return False
    
    print(f"Built {OUTPUT_ELF}")
    
    # Extract binary
    cmd_objcopy = [
        'arm-none-eabi-objcopy',
        '-O', 'binary',
        OUTPUT_ELF,
        OUTPUT_BIN,
    ]
    
    result = subprocess.run(cmd_objcopy, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("objcopy failed!")
        print("STDERR:", result.stderr)
        return False
    
    print(f"Created {OUTPUT_BIN}")
    
    # Show symbol table
    cmd_nm = ['arm-none-eabi-nm', '-n', OUTPUT_ELF]
    result = subprocess.run(cmd_nm, capture_output=True, text=True)
    if result.returncode == 0:
        print("\nSymbol table:")
        for line in result.stdout.split('\n')[:30]:  # First 30 symbols
            if line.strip():
                print(f"  {line}")
        print("  ...")
    
    return True


def get_symbol_address(symbol_name: str) -> int:
    """Get the address of a symbol from the ELF file"""
    cmd = ['arm-none-eabi-nm', OUTPUT_ELF]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return None
    
    for line in result.stdout.split('\n'):
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol_name:
            return int(parts[0], 16)
    
    return None


def get_all_symbols() -> dict:
    """Get all symbols from the ELF file"""
    cmd = ['arm-none-eabi-nm', OUTPUT_ELF]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    symbols = {}
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                addr = int(parts[0], 16)
                name = parts[2]
                symbols[name] = addr
    
    return symbols


if __name__ == '__main__':
    if not build():
        sys.exit(1)
    
    print("\nKey symbols:")
    symbols = get_all_symbols()
    for name in ['decrypt', 'chaff', 'workspace_start', 'rkey_s', 'lut_a', 'lut_b']:
        if name in symbols:
            print(f"  {name}: 0x{symbols[name]:08x}")
