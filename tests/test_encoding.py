"""Tests for text, hex, Base64 and bit conversions, and for the padding rules."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.encoding_utils import (
    InputValidationError,
    bits_to_bytes,
    bits_to_string,
    bytes_to_bits,
    bytes_to_text,
    parse_base64,
    parse_binary,
    parse_hex,
    parse_int,
    text_to_bytes,
    to_base64,
    to_binary,
    to_hex,
    unpack_bits,
)
from algorithms.xor_utils import xor_bits, xor_bytes


class TextTests(unittest.TestCase):
    def test_utf8_round_trip(self):
        for text in ("Hello", "Mixed CASE 123 !?", "مرحبا بالعالم", "你好", "🙂"):
            self.assertEqual(bytes_to_text(text_to_bytes(text)), text)

    def test_arabic_letters_take_two_bytes(self):
        self.assertEqual(len(text_to_bytes("مرحبا")), 10)

    def test_invalid_utf8_returns_none(self):
        self.assertIsNone(bytes_to_text(b"\xff\xfe"))

    def test_lone_surrogate_is_a_clean_error(self):
        with self.assertRaises(InputValidationError):
            text_to_bytes("\ud800")


class HexTests(unittest.TestCase):
    def test_parsing(self):
        self.assertEqual(parse_hex("0aFF"), b"\x0a\xff")
        self.assertEqual(parse_hex("0a ff\n01"), b"\x0a\xff\x01")

    def test_invalid_characters(self):
        with self.assertRaises(InputValidationError):
            parse_hex("zz")

    def test_odd_length(self):
        with self.assertRaises(InputValidationError):
            parse_hex("abc")

    def test_output_is_uppercase(self):
        self.assertEqual(to_hex(b"\xab\x01"), "AB01")


class Base64Tests(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(parse_base64(to_base64(b"any data")), b"any data")

    def test_invalid_characters(self):
        with self.assertRaises(InputValidationError):
            parse_base64("not base64!")

    def test_invalid_padding(self):
        with self.assertRaises(InputValidationError):
            parse_base64("QUJD=")

    def test_non_ascii_is_rejected(self):
        with self.assertRaises(InputValidationError):
            parse_base64("مرحبا")


class BitTests(unittest.TestCase):
    def test_byte_expands_msb_first(self):
        self.assertEqual(bytes_to_bits(b"H"), [0, 1, 0, 0, 1, 0, 0, 0])

    def test_packing_is_msb_first(self):
        self.assertEqual(bits_to_bytes([0, 1, 0, 0, 1, 0, 0, 0]), b"H")

    def test_partial_byte_is_padded_with_zeros_on_the_right(self):
        self.assertEqual(bits_to_bytes([1]), b"\x80")
        self.assertEqual(bits_to_bytes([1, 0, 1]), b"\xa0")

    def test_114_bits_pack_into_15_bytes(self):
        self.assertEqual(len(bits_to_bytes([1] * 114)), 15)
        self.assertEqual(bits_to_bytes([1] * 114)[-1], 0b11000000)

    def test_unpack_removes_the_padding(self):
        bits = [1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1]
        self.assertEqual(unpack_bits(bits_to_bytes(bits), len(bits)), bits)

    def test_string_forms(self):
        self.assertEqual(bits_to_string([1, 0, 1]), "101")
        self.assertEqual(to_binary(b"A"), "01000001")

    def test_binary_parsing(self):
        self.assertEqual(parse_binary("10 1\n1"), [1, 0, 1, 1])
        with self.assertRaises(InputValidationError):
            parse_binary("102")


class IntegerTests(unittest.TestCase):
    def test_accepted_forms(self):
        self.assertEqual(parse_int(308, "f", "x", 0, 1000), 308)
        self.assertEqual(parse_int("308", "f", "x", 0, 1000), 308)
        self.assertEqual(parse_int("0x134", "f", "x", 0, 1000), 308)
        self.assertEqual(parse_int(" 0X134 ", "f", "x", 0, 1000), 308)

    def test_rejected_forms(self):
        for value in (True, 1.5, "abc", "1_000", "-1", "", None, "٣"):
            with self.assertRaises(InputValidationError):
                parse_int(value, "f", "x", 0, 1000)

    def test_range(self):
        with self.assertRaises(InputValidationError):
            parse_int(1001, "f", "x", 0, 1000)


class XorTests(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(xor_bytes(b"\x0f\xf0", b"\xff\xff"), b"\xf0\x0f")

    def test_bits(self):
        self.assertEqual(xor_bits([0, 0, 1, 1], [0, 1, 0, 1]), [0, 1, 1, 0])

    def test_xor_is_its_own_inverse(self):
        self.assertEqual(xor_bytes(xor_bytes(b"data", b"keys"), b"keys"), b"data")

    def test_length_mismatch(self):
        with self.assertRaises(ValueError):
            xor_bytes(b"a", b"ab")
        with self.assertRaises(ValueError):
            xor_bits([0], [0, 1])


if __name__ == "__main__":
    unittest.main()
