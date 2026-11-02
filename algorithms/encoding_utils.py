"""Conversions between text, bytes and bit sequences, plus input parsing.

Bit-order convention used throughout the project
------------------------------------------------
A byte is expanded to bits most significant bit first, so "H" (0x48) becomes
``[0, 1, 0, 0, 1, 0, 0, 0]``. Bit sequences are packed back the same way. When a
sequence is not a whole number of bytes, zero bits are appended to the *serialized*
form only, and the meaningful length has to be recorded separately. This matches the
packing of the published A5/1 test vectors (114 bits + 6 zero bits = 15 bytes).
"""

from __future__ import annotations

import base64
import binascii
import re


class InputValidationError(ValueError):
    """User input that cannot be processed. The message is safe to show to users."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.message = message
        self.field = field


_HEX_RE = re.compile(r"[0-9a-fA-F]*")
_INT_RE = re.compile(r"(0[xX][0-9a-fA-F]+|[0-9]+)")
_WHITESPACE_RE = re.compile(r"\s+")


def text_to_bytes(text: str, field: str | None = None) -> bytes:
    """Encode text as UTF-8. Raises for lone surrogates, which UTF-8 cannot represent."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InputValidationError("The text contains characters that cannot be encoded as UTF-8.", field) from exc


def bytes_to_text(data: bytes) -> str | None:
    """Decode UTF-8 strictly. Returns None when the bytes are not valid UTF-8."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_hex(value: str, field: str | None = None, label: str = "Hexadecimal input") -> bytes:
    """Parse a hexadecimal string. Whitespace between digits is ignored."""
    cleaned = _WHITESPACE_RE.sub("", value)
    if not _HEX_RE.fullmatch(cleaned):
        raise InputValidationError(f"{label} may only contain the characters 0-9 and A-F.", field)
    if len(cleaned) % 2:
        raise InputValidationError(f"{label} must contain an even number of hexadecimal characters.", field)
    return bytes.fromhex(cleaned)


def parse_base64(value: str, field: str | None = None, label: str = "Base64 input") -> bytes:
    """Parse standard Base64 strictly. Whitespace between characters is ignored."""
    cleaned = _WHITESPACE_RE.sub("", value)
    try:
        return base64.b64decode(cleaned.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise InputValidationError(f"{label} is not valid Base64.", field) from exc


def parse_binary(value: str, field: str | None = None, label: str = "Binary input") -> list[int]:
    """Parse a string of 0s and 1s into a bit list. Whitespace is ignored."""
    cleaned = _WHITESPACE_RE.sub("", value)
    if any(c not in "01" for c in cleaned):
        raise InputValidationError(f"{label} may only contain the characters 0 and 1.", field)
    return [int(c) for c in cleaned]


def parse_int(value: object, field: str, label: str, minimum: int, maximum: int, hint: str = "") -> int:
    """Parse a JSON integer, or a decimal or 0x-prefixed string, and check its range."""
    if isinstance(value, bool):
        raise InputValidationError(f"{label} must be a whole number.", field)
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and _INT_RE.fullmatch(value.strip()):
        text = value.strip()
        number = int(text, 16) if text[:2].lower() == "0x" else int(text, 10)
    else:
        raise InputValidationError(f"{label} must be a decimal number or a hexadecimal number starting with 0x.", field)
    if not minimum <= number <= maximum:
        raise InputValidationError(f"{label} must be between {minimum} and {maximum}{hint}.", field)
    return number


def bytes_to_bits(data: bytes) -> list[int]:
    """Expand bytes to bits, most significant bit of each byte first."""
    return [(byte >> (7 - offset)) & 1 for byte in data for offset in range(8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack bits MSB-first, padding the final byte with zero bits if necessary."""
    packed = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            packed[index // 8] |= 1 << (7 - index % 8)
    return bytes(packed)


def unpack_bits(data: bytes, bit_length: int) -> list[int]:
    """Recover exactly ``bit_length`` bits from a packed value, dropping the padding."""
    return bytes_to_bits(data)[:bit_length]


def bits_to_string(bits: list[int]) -> str:
    return "".join("1" if bit else "0" for bit in bits)


def to_hex(data: bytes) -> str:
    return data.hex().upper()


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def to_binary(data: bytes) -> str:
    return bits_to_string(bytes_to_bits(data))
