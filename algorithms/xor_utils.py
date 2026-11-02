"""XOR helpers shared by both ciphers.

XOR is its own inverse: (P ^ K) ^ K == P. That single property is why a stream cipher
uses the same operation, and the same keystream, to encrypt and to decrypt.
"""

from __future__ import annotations


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length.")
    return bytes(a ^ b for a, b in zip(left, right))


def xor_bits(left: list[int], right: list[int]) -> list[int]:
    """XOR two equal-length bit sequences."""
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length.")
    return [a ^ b for a, b in zip(left, right)]
