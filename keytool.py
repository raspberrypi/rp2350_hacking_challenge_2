#!/usr/bin/env python3
"""
4‑way XOR secret‑sharing for a 256‑bit key
=========================================

Memory layout on encode
-----------------------
    r0  →  64 bytes: a0 b0 c0 d0 … a3 b3 c3 d3
          64 bytes: a4 b4 c4 d4 … a7 b7 c7 d7

CLI
---
Encode a 32‑byte key (64 hex chars) into the layout above:

    python xor_split.py encode 0123456789abcdeffedcba9876543210\
                             00112233445566778899aabbccddeeff

Same, but emit as a C‑style escaped string (two lines = two 64‑byte blocks):

    python xor_split.py encode <key‑hex> -c

Decode the two 64‑byte blocks back into the key:

    python xor_split.py decode <block0‑hex> <block1‑hex>
    python xor_split.py decode <block0‑hex> <block1‑hex> --c-array
"""

import os
import sys
import argparse
from functools import reduce
from typing import List, Tuple

WORD   = 4   # bytes
WORDS  = 8   # words in the 256‑bit key
SHARES = 4   # split count
BLOCK  = 64  # bytes per ½ key layout


# ---------- helpers ---------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal‑length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def xor_reduce(chunks: List[bytes]) -> bytes:
    """XOR a list of equal‑length byte strings."""
    return reduce(xor_bytes, chunks, b"\x00" * len(chunks[0]))


def to_c_array(data: bytes) -> str:
    """Convert raw bytes to an escaped C‑style hex string."""
    return "".join(f"\\x{b:02x}" for b in data)


# ---------- core ------------------------------------------------------------

def encode(key_hex: str) -> Tuple[bytes, bytes]:
    """
    Split a 256‑bit key (64 hex chars) into 4‑way shares laid out as:

        64‑byte block 0  |  64‑byte block 1
        ---------------------------------------------------
        a0 b0 c0 d0 ... a3 b3 c3 d3       a4 ... d7
    """
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Key must be valid hexadecimal.")

    if len(key) != WORD * WORDS:
        raise ValueError("Key must be exactly 32 bytes (64 hex characters).")

    share_words: List[bytes] = []
    # Process each 32‑bit word of the key separately
    for i in range(0, len(key), WORD):
        k_word = key[i : i + WORD]               # original word K
        a = os.urandom(WORD)
        b = os.urandom(WORD)
        c = os.urandom(WORD)
        d = xor_reduce([k_word, a, b, c])        # ensure a ⊕ b ⊕ c ⊕ d = K
        share_words.extend([a, b, c, d])

    share_data = b"".join(share_words)           # 128 bytes
    return share_data[:BLOCK], share_data[BLOCK:]  # block0, block1


def decode(blocks_hex: List[str]) -> bytes:
    """
    Recombine two 64‑byte blocks of 4‑way shares back into the 256‑bit key.
    """
    if len(blocks_hex) != 2:
        raise ValueError("Exactly two blocks (block0, block1) are required.")

    try:
        block0, block1 = (bytes.fromhex(h) for h in blocks_hex)
    except ValueError:
        raise ValueError("Blocks must be valid hexadecimal.")

    if len(block0) != BLOCK or len(block1) != BLOCK:
        raise ValueError("Each block must be exactly 64 bytes (128 hex characters).")

    share_data = block0 + block1                 # 128 bytes, interleaved
    key_words: List[bytes] = []

    # Every 16 bytes = four 32‑bit shares for one key word
    for i in range(0, len(share_data), WORD * SHARES):
        a, b, c, d = (
            share_data[i + 0 : i + WORD],
            share_data[i + WORD : i + 2 * WORD],
            share_data[i + 2 * WORD : i + 3 * WORD],
            share_data[i + 3 * WORD : i + 4 * WORD],
        )
        key_words.append(xor_reduce([a, b, c, d]))

    return b"".join(key_words)


# ---------- CLI -------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="4‑way XOR secret‑sharing tool")
    parser.add_argument(
        "-c",
        "--c-array",
        action="store_true",
        help="output in C‑style escaped hex (\\x00\\x11...)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encode", help="split key into shares")
    enc.add_argument("key_hex", metavar="KEY", help="64‑hex‑character key")

    dec = subparsers.add_parser("decode", help="recombine shares to key")
    dec.add_argument(
        "blocks", nargs=2, metavar="BLOCK", help="128‑hex‑character 64‑byte block"
    )

    args = parser.parse_args()

    try:
        if args.command == "encode":
            block0, block1 = encode(args.key_hex)
            if args.c_array:
                # Print each 64‑byte block as a standalone escaped string
                print(to_c_array(block0))
                print(to_c_array(block1))
            else:
                # Raw lowercase hex, one line per block
                print(block0.hex())
                print(block1.hex())
        elif args.command == "decode":
            key = decode(args.blocks)
            print(to_c_array(key) if args.c_array else key.hex())
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
