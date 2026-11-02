"""A5/1 tests against the Briceno-Goldberg-Wagner vector and an Osmocom vector."""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms import a51
from algorithms.encoding_utils import InputValidationError, bits_to_bytes, bytes_to_bits, unpack_bits
from services.cipher_service import encrypt
from services.trace_service import build_visualization

KEY = bytes.fromhex("1223456789ABCDEF")
COUNT = 0x134
DOWNLINK_HEX = "534EAA582FE8151AB6E1855A728C00"
UPLINK_HEX = "24FD35A35D5FB6526D32F906DF1AC0"

# libosmocore tests/a5/a5_test.c. Osmocom reads key[7 - (i >> 3)], so its key bytes are reversed here.
OSMOCOM_KEY = bytes.fromhex("0123456789ABCDEF")[::-1]
OSMOCOM_FN = 123456
OSMOCOM_DOWNLINK_HEX = "CBA25576175D3B1C7B2F29A8C1B600"
OSMOCOM_UPLINK_HEX = "D9035E0F2AEC139A05D4A87BB16480"


class RegisterTests(unittest.TestCase):
    def test_lengths_and_masks(self):
        self.assertEqual((a51.R1.length, a51.R2.length, a51.R3.length), (19, 22, 23))
        self.assertEqual((a51.R1.mask, a51.R2.mask, a51.R3.mask), (0x07FFFF, 0x3FFFFF, 0x7FFFFF))

    def test_tap_masks_match_the_reference_code(self):
        self.assertEqual((a51.R1.tap_mask, a51.R2.tap_mask, a51.R3.tap_mask), (0x072000, 0x300000, 0x700080))

    def test_clock_and_output_positions(self):
        self.assertEqual((a51.R1.clock_bit, a51.R2.clock_bit, a51.R3.clock_bit), (8, 10, 10))
        self.assertEqual((a51.R1.output_bit, a51.R2.output_bit, a51.R3.output_bit), (18, 21, 22))

    def test_feedback_is_the_xor_of_the_taps(self):
        self.assertEqual(a51.feedback_bit(1 << 13, a51.R1), 1)
        self.assertEqual(a51.feedback_bit((1 << 13) | (1 << 16), a51.R1), 0)
        self.assertEqual(a51.feedback_bit(1 << 7, a51.R3), 1)
        # Bit 12 is not a tap of R1.
        self.assertEqual(a51.feedback_bit(1 << 12, a51.R1), 0)

    def test_clocking_shifts_and_inserts_feedback(self):
        self.assertEqual(a51.clock_register(0b1, a51.R1), 0b10)
        self.assertEqual(a51.clock_register(1 << 13, a51.R1), (1 << 14) | 1)

    def test_registers_never_exceed_their_length(self):
        for spec in a51.REGISTERS:
            self.assertLessEqual(a51.clock_register(spec.mask, spec), spec.mask)

    def test_clock_bit_extraction(self):
        cipher = a51.A51()
        cipher.r1, cipher.r2, cipher.r3 = 1 << 8, 1 << 10, 0
        self.assertEqual(cipher.clock_bits(), (1, 1, 0))


class MajorityTests(unittest.TestCase):
    def test_truth_table(self):
        for a in (0, 1):
            for b in (0, 1):
                for c in (0, 1):
                    self.assertEqual(a51.majority(a, b, c), 1 if a + b + c >= 2 else 0)

    def test_only_matching_registers_advance(self):
        cipher = a51.A51()
        cipher.r1, cipher.r2, cipher.r3 = (1 << 8) | 1, 1, (1 << 10) | 1
        r2_before = cipher.r2
        moved = cipher.clock_majority()
        self.assertEqual(moved, (True, False, True))
        self.assertEqual(cipher.r2, r2_before)
        self.assertNotEqual(cipher.r1, (1 << 8) | 1)

    def test_at_least_two_registers_advance_every_normal_cycle(self):
        steps = []
        a51.generate_frame(KEY, COUNT, steps.append)
        normal = [step for step in steps if step.majority is not None]
        self.assertEqual(len(normal), 328)
        for step in normal:
            self.assertGreaterEqual(sum(step.moved), 2)
            for bit, moved in zip(step.clock_bits, step.moved):
                self.assertEqual(moved, bit == step.majority)

    def test_stationary_registers_keep_their_value(self):
        steps = []
        a51.generate_frame(KEY, COUNT, steps.append)
        for step in steps:
            for before, after, moved in zip(step.before, step.after_clock, step.moved):
                if not moved:
                    self.assertEqual(before, after)


class KeySetupTests(unittest.TestCase):
    def setUp(self):
        self.steps = []
        a51.generate_frame(KEY, COUNT, self.steps.append)

    def test_phase_sizes(self):
        counts = {}
        for step in self.steps:
            counts[step.phase] = counts.get(step.phase, 0) + 1
        self.assertEqual(counts, {"key": 64, "count": 22, "warmup": 100, "downlink": 114, "uplink": 114})

    def test_key_bits_load_in_byte_order_lsb_first(self):
        loaded = [step.input_bit for step in self.steps if step.phase == "key"]
        # 0x12 = 0b00010010, read from its least significant bit.
        self.assertEqual(loaded[:8], [0, 1, 0, 0, 1, 0, 0, 0])
        self.assertEqual(loaded, [a51.key_bit(KEY, position) for position in range(64)])

    def test_count_bits_load_lsb_first(self):
        loaded = [step.input_bit for step in self.steps if step.phase == "count"]
        self.assertEqual(loaded, [(COUNT >> position) & 1 for position in range(22)])

    def test_loading_clocks_every_register_and_injects_at_bit_zero(self):
        for step in self.steps:
            if step.phase not in ("key", "count"):
                continue
            self.assertEqual(step.moved, (True, True, True))
            self.assertIsNone(step.majority)
            for spec, before, clocked, after in zip(a51.REGISTERS, step.before, step.after_clock, step.after):
                self.assertEqual(clocked, a51.clock_register(before, spec))
                self.assertEqual(after, clocked ^ step.input_bit)

    def test_warmup_uses_majority_clocking(self):
        warmup = [step for step in self.steps if step.phase == "warmup"]
        self.assertEqual(len(warmup), 100)
        self.assertTrue(all(step.majority is not None for step in warmup))

    def test_output_is_read_after_clocking(self):
        for step in self.steps:
            if step.phase in ("downlink", "uplink"):
                expected = (
                    a51.get_bit(step.after[0], 18) ^ a51.get_bit(step.after[1], 21) ^ a51.get_bit(step.after[2], 22)
                )
                self.assertEqual(step.output, expected)


class ReferenceVectorTests(unittest.TestCase):
    def test_reference_sequences_are_exact(self):
        frame = a51.generate_frame(KEY, COUNT)
        self.assertEqual(len(frame.downlink), 114)
        self.assertEqual(len(frame.uplink), 114)
        self.assertEqual(bits_to_bytes(frame.downlink).hex().upper(), DOWNLINK_HEX)
        self.assertEqual(bits_to_bytes(frame.uplink).hex().upper(), UPLINK_HEX)

    def test_meaningful_bits_match_without_the_padding(self):
        frame = a51.generate_frame(KEY, COUNT)
        self.assertEqual(frame.downlink, unpack_bits(bytes.fromhex(DOWNLINK_HEX), 114))
        self.assertEqual(frame.uplink, unpack_bits(bytes.fromhex(UPLINK_HEX), 114))
        self.assertEqual(bytes_to_bits(bytes.fromhex(DOWNLINK_HEX))[114:], [0] * 6)

    def test_direction_selection(self):
        frame = a51.generate_frame(KEY, COUNT)
        self.assertEqual(frame.sequence(a51.DOWNLINK), frame.downlink)
        self.assertEqual(frame.sequence(a51.UPLINK), frame.uplink)
        zeros = [0] * 114
        self.assertEqual(a51.crypt_bits(KEY, zeros, a51.DOWNLINK, COUNT).output, frame.downlink)
        self.assertEqual(a51.crypt_bits(KEY, zeros, a51.UPLINK, COUNT).output, frame.uplink)

    def test_osmocom_vector_with_frame_number(self):
        frame = a51.generate_frame(OSMOCOM_KEY, a51.fn_to_count(OSMOCOM_FN))
        self.assertEqual(bits_to_bytes(frame.downlink).hex().upper(), OSMOCOM_DOWNLINK_HEX)
        self.assertEqual(bits_to_bytes(frame.uplink).hex().upper(), OSMOCOM_UPLINK_HEX)

    def test_fn_and_count_are_not_interchangeable(self):
        self.assertNotEqual(a51.fn_to_count(OSMOCOM_FN), OSMOCOM_FN)
        self.assertNotEqual(a51.generate_frame(OSMOCOM_KEY, OSMOCOM_FN).downlink, a51.generate_frame(OSMOCOM_KEY, a51.fn_to_count(OSMOCOM_FN)).downlink)

    def test_fn_conversion_components(self):
        fn = OSMOCOM_FN
        t1, t2, t3 = a51.fn_components(fn)
        self.assertEqual((t1, t2, t3), (fn // 1326, fn % 26, fn % 51))
        self.assertEqual(a51.fn_to_count(fn), (t1 << 11) | (t3 << 5) | t2)
        self.assertLessEqual(a51.fn_to_count(a51.MAX_FN), a51.MAX_COUNT)


class MessageLengthTests(unittest.TestCase):
    @staticmethod
    def random_bits(length, seed=455):
        generator = random.Random(seed)
        return [generator.randint(0, 1) for _ in range(length)]

    def test_short_message_uses_only_the_bits_it_needs(self):
        bits = bytes_to_bits(b"HI")
        result = a51.crypt_bits(KEY, bits, a51.DOWNLINK, COUNT)
        frame = a51.generate_frame(KEY, COUNT)
        self.assertEqual(len(result.output), 16)
        self.assertEqual(result.keystream, frame.downlink[:16])
        self.assertEqual(len(result.segments), 1)
        self.assertEqual(a51.crypt_bits(KEY, result.output, a51.DOWNLINK, COUNT).output, bits)

    def test_short_message_report_matches_the_specification(self):
        response = encrypt({"algorithm": "a51", "key": KEY.hex(), "count": "0x134", "plaintext": "HI"})
        self.assertEqual(response["plaintext"]["bit_length"], 16)
        self.assertEqual(response["keystream"]["bits_generated"], 114)
        self.assertEqual(response["keystream"]["bits_used"], 16)
        self.assertEqual(response["keystream"]["bits_unused"], 98)
        self.assertEqual(response["ciphertext"]["bit_length"], 16)

    def test_exactly_114_bits(self):
        bits = self.random_bits(114)
        result = a51.crypt_bits(KEY, bits, a51.UPLINK, COUNT)
        self.assertEqual(len(result.segments), 1)
        self.assertEqual(result.segments[0].length, 114)
        self.assertEqual(a51.crypt_bits(KEY, result.output, a51.UPLINK, COUNT).output, bits)

    def test_200_bits_need_two_segments(self):
        segments = a51.build_segments(200, start_count=COUNT)
        self.assertEqual([(s.length, s.count, s.start_bit) for s in segments], [(114, COUNT, 0), (86, COUNT + 1, 114)])

    def test_multi_frame_processing(self):
        bits = self.random_bits(500)
        result = a51.crypt_bits(KEY, bits, a51.DOWNLINK, COUNT)
        self.assertEqual(len(result.segments), 5)
        self.assertEqual(a51.crypt_bits(KEY, result.output, a51.DOWNLINK, COUNT).output, bits)
        expected = a51.generate_frame(KEY, COUNT).downlink + a51.generate_frame(KEY, COUNT + 1).downlink
        self.assertEqual(result.keystream[:228], expected)

    def test_count_wraps_at_22_bits(self):
        segments = a51.build_segments(200, start_count=a51.MAX_COUNT)
        self.assertEqual([segment.count for segment in segments], [a51.MAX_COUNT, 0])

    def test_fn_mode_advances_fn_and_derives_count(self):
        segments = a51.build_segments(200, start_fn=OSMOCOM_FN)
        self.assertEqual(segments[1].fn, OSMOCOM_FN + 1)
        self.assertEqual(segments[1].count, a51.fn_to_count(OSMOCOM_FN + 1))
        wrapped = a51.build_segments(200, start_fn=a51.MAX_FN)
        self.assertEqual(wrapped[1].fn, 0)
        self.assertEqual(wrapped[1].count, 0)

    def test_exact_bit_length_is_preserved(self):
        for length in (1, 7, 9, 113, 115, 229):
            bits = self.random_bits(length, seed=length)
            output = a51.crypt_bits(KEY, bits, a51.DOWNLINK, COUNT).output
            self.assertEqual(len(output), length)
            self.assertEqual(unpack_bits(bits_to_bytes(output), length), output)


class ValidationTests(unittest.TestCase):
    def test_wrong_key_length(self):
        for key in (b"", bytes(7), bytes(9)):
            with self.assertRaises(InputValidationError):
                a51.generate_frame(key, COUNT)

    def test_count_out_of_range(self):
        for count in (-1, a51.COUNT_MODULUS):
            with self.assertRaises(InputValidationError):
                a51.generate_frame(KEY, count)

    def test_invalid_direction(self):
        with self.assertRaises(InputValidationError):
            a51.crypt_bits(KEY, [0], "sideways", COUNT)

    def test_fn_out_of_range(self):
        with self.assertRaises(InputValidationError):
            a51.fn_to_count(a51.FN_MODULUS)


class TraceTests(unittest.TestCase):
    PAYLOAD = {"algorithm": "a51", "key": KEY.hex(), "count": "0x134", "plaintext": "HI"}

    def all_steps(self, payload=None):
        payload = payload or self.PAYLOAD
        first = build_visualization({**payload, "start": 0, "count_steps": 128})
        steps = list(first["steps"])
        while len(steps) < first["total_steps"]:
            page = build_visualization({**payload, "start": len(steps), "count_steps": 128})
            steps.extend(page["steps"])
        return first["summary"], steps

    def test_phase_layout(self):
        summary, steps = self.all_steps()
        layout = [(phase["id"], phase["count"]) for phase in summary["phases"]]
        self.assertEqual(layout, [("clear", 1), ("key", 64), ("count", 22), ("loaded", 1), ("warmup", 100), ("keystream", 228), ("xor", 16)])
        self.assertEqual(len(steps), 432)
        for phase in summary["phases"]:
            for step in steps[phase["start"] : phase["start"] + phase["count"]]:
                self.assertEqual(step["phase"], phase["id"])

    def test_register_states_match_the_algorithm(self):
        truth = []
        a51.generate_frame(KEY, COUNT, truth.append)
        _, steps = self.all_steps()
        clocked = [step for step in steps if step["phase"] in ("key", "count", "warmup", "keystream")]
        self.assertEqual(len(clocked), len(truth))
        for step, expected in zip(clocked, truth):
            self.assertEqual(step["registers"], list(expected.after))
            self.assertEqual(step["registers_before"], list(expected.before))
            self.assertEqual(step["moved"], list(expected.moved))

    def test_each_step_continues_from_the_previous_snapshot(self):
        _, steps = self.all_steps()
        clocked = [step for step in steps if "registers" in step]
        for previous, current in zip(clocked, clocked[1:]):
            self.assertEqual(previous["registers"], current["registers_before"])

    def test_trace_keystream_matches_the_reference_vector(self):
        summary, steps = self.all_steps()
        generated = [step["keystream_bit"] for step in steps if step["phase"] == "keystream"]
        self.assertEqual(bits_to_bytes(generated[:114]).hex().upper(), DOWNLINK_HEX)
        self.assertEqual(bits_to_bytes(generated[114:]).hex().upper(), UPLINK_HEX)
        self.assertEqual(summary["downlink"], "".join(map(str, generated[:114])))

    def test_trace_ciphertext_matches_direct_output(self):
        summary, steps = self.all_steps()
        direct = encrypt(self.PAYLOAD)
        self.assertEqual(summary["ciphertext_hex"], direct["ciphertext"]["hex"])
        xor_bits = [step["ciphertext_bit"] for step in steps if step["phase"] == "xor"]
        self.assertEqual(bits_to_bytes(xor_bits).hex().upper(), direct["ciphertext"]["hex"])

    def test_warmup_counter_text(self):
        response = build_visualization({**self.PAYLOAD, "phase": "warmup", "start": 88 + 34, "count_steps": 1})
        self.assertEqual(response["steps"][0]["counter"], "Warm-up cycle 35 / 100")

    def test_majority_explanation_names_the_registers(self):
        _, steps = self.all_steps()
        for step in (item for item in steps if item["phase"] == "warmup"):
            still = [name for name, moved in zip(("R1", "R2", "R3"), step["moved"]) if not moved]
            if still:
                self.assertIn(f"{still[0]} remains unchanged", step["explanation"])
            else:
                self.assertIn("all three registers advance", step["explanation"])

    def test_multi_frame_trace(self):
        payload = {**self.PAYLOAD, "plaintext": "A" * 25}
        summary, steps = self.all_steps(payload)
        self.assertEqual(summary["segment_count"], 2)
        direct = encrypt(payload)
        self.assertEqual(summary["ciphertext_hex"], direct["ciphertext"]["hex"])
        xor = [step for step in steps if step["phase"] == "xor"]
        self.assertEqual(xor[113]["segment"], 0)
        self.assertEqual(xor[114]["segment"], 1)
        self.assertEqual(xor[114]["count"], COUNT + 1)
        self.assertIn("reinitialized", xor[114]["explanation"])

    def test_selecting_a_segment_traces_that_frame(self):
        payload = {**self.PAYLOAD, "plaintext": "A" * 25, "segment": 1}
        summary, steps = self.all_steps(payload)
        self.assertEqual(summary["traced_count"], COUNT + 1)
        frame = a51.generate_frame(KEY, COUNT + 1)
        generated = [step["keystream_bit"] for step in steps if step["phase"] == "keystream"]
        self.assertEqual(generated[:114], frame.downlink)


if __name__ == "__main__":
    unittest.main()
