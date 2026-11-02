"""RC4 tests, using RFC 6229 as the primary reference."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms import rc4
from algorithms.encoding_utils import InputValidationError
from services.trace_service import build_visualization, simplified_rc4

# RFC 6229 section 2: key -> {keystream offset: 16 bytes of expected output}.
RFC6229_VECTORS = {
    "0102030405": {
        0: "b2396305f03dc027ccc3524a0a1118a8",
        16: "6982944f18fc82d589c403a47a0d0919",
        240: "28cb1132c96ce286421dcaadb8b69eae",
        4080: "068326a2118416d21f9d04b2cd1ca050",
    },
    "01020304050607": {
        0: "293f02d47f37c9b633f2af5285feb46b",
        16: "e620f1390d19bd84e2e0fd752031afc1",
        240: "914f02531c9218810df60f67e338154c",
        4080: "f3172ceffc3b3d997c85ccd5af1a950c",
    },
    "0102030405060708": {
        0: "97ab8a1bf0afb96132f2f67258da15a8",
        16: "8263efdb45c4a18684ef87e6b19e5b09",
        240: "9636ebc9841926f4f7d1f362bddf6e18",
        4080: "d5fa5a3469d29aaaf83d23589db8c85b",
    },
    "0102030405060708090a0b0c0d0e0f10": {
        0: "9ac7cc9a609d1ef7b2932899cde41b97",
        16: "5248c4959014126a6e8a84f11d1a9e1c",
        240: "065902e4b620f6cc36c8589f66432f2b",
        4080: "ff38265c1642c1abe8d3c2fe5e572bf8",
    },
}


class KsaTests(unittest.TestCase):
    def test_trace_starts_from_identity_array(self):
        response = build_visualization({"algorithm": "rc4", "key": "Key", "plaintext": "A", "count_steps": 1})
        self.assertEqual(response["steps"][0]["S"], list(range(256)))

    def test_result_is_a_permutation(self):
        for key in (b"\x00", b"Key", bytes(range(256))):
            self.assertEqual(sorted(rc4.ksa(key)), list(range(256)))

    def test_every_iteration_stays_a_permutation(self):
        steps = []
        rc4.ksa(b"Secret", steps.append)
        self.assertEqual(len(steps), 256)
        for step in steps:
            self.assertEqual(sorted(step.state), list(range(256)))

    def test_first_iteration_matches_the_formula(self):
        steps = []
        rc4.ksa(bytes([1, 2, 3]), steps.append)
        first = steps[0]
        # j = (0 + S[0] + key[0]) mod 256 = (0 + 0 + 1) mod 256 = 1
        self.assertEqual((first.i, first.previous_j, first.s_i, first.key_byte, first.j), (0, 0, 0, 1, 1))
        self.assertEqual(first.state[:2], (1, 0))

    def test_key_bytes_repeat_cyclically(self):
        steps = []
        rc4.ksa(bytes([9, 8, 7]), steps.append)
        self.assertEqual([step.key_byte for step in steps[:7]], [9, 8, 7, 9, 8, 7, 9])

    def test_different_keys_give_different_permutations(self):
        self.assertNotEqual(rc4.ksa(b"Key1"), rc4.ksa(b"Key2"))

    def test_observer_does_not_change_the_result(self):
        self.assertEqual(rc4.ksa(b"Key", lambda step: None), rc4.ksa(b"Key"))


class PrgaTests(unittest.TestCase):
    def test_rfc6229_vectors(self):
        for key_hex, offsets in RFC6229_VECTORS.items():
            stream = rc4.rc4_keystream(bytes.fromhex(key_hex), 4096)
            for offset, expected in offsets.items():
                with self.subTest(key=key_hex, offset=offset):
                    self.assertEqual(stream[offset : offset + 16].hex(), expected)

    def test_state_keeps_changing_during_generation(self):
        steps = []
        state = rc4.ksa(b"Key")
        rc4.prga(state, 5, steps.append)
        snapshots = {step.state for step in steps}
        self.assertGreater(len(snapshots), 1)
        for step in steps:
            self.assertEqual(sorted(step.state), list(range(256)))

    def test_prga_function_matches_the_rc4_class(self):
        self.assertEqual(rc4.prga(rc4.ksa(b"Key"), 300), rc4.RC4(b"Key").keystream(300))

    def test_keystream_continues_across_calls(self):
        cipher = rc4.RC4(b"Key")
        self.assertEqual(cipher.keystream(10) + cipher.keystream(10), rc4.rc4_keystream(b"Key", 20))

    def test_step_values_are_consistent(self):
        steps = []
        rc4.prga(rc4.ksa(b"Key"), 20, steps.append)
        for step in steps:
            self.assertEqual(step.t, (step.s_i + step.s_j) % 256)
            self.assertEqual(step.state[step.t], step.keystream_byte)
            self.assertEqual(step.state[step.i], step.s_j)
            self.assertEqual(step.state[step.j], step.s_i if step.i != step.j else step.s_j)


class EncryptionTests(unittest.TestCase):
    def test_published_key_plaintext_vector(self):
        self.assertEqual(rc4.rc4_crypt(b"Key", b"Plaintext").hex().upper(), "BBF316E8D940AF0AD3")

    def test_symmetry(self):
        message = b"Attack at dawn"
        self.assertEqual(rc4.rc4_crypt(b"Secret", rc4.rc4_crypt(b"Secret", message)), message)

    def test_output_length_equals_input_length(self):
        for message in (b"A", b"HI", b"Hello World"):
            self.assertEqual(len(rc4.rc4_crypt(b"Key", message)), len(message))

    def test_long_plaintext(self):
        message = bytes(range(256)) * 200
        self.assertEqual(rc4.rc4_crypt(b"Key", rc4.rc4_crypt(b"Key", message)), message)

    def test_unicode_plaintext(self):
        message = "مرحبا Grüße 你好 🙂".encode("utf-8")
        self.assertEqual(rc4.rc4_crypt(b"Key", rc4.rc4_crypt(b"Key", message)).decode("utf-8"), "مرحبا Grüße 你好 🙂")

    def test_different_keys_give_different_ciphertext(self):
        self.assertNotEqual(rc4.rc4_crypt(b"Key1", b"Plaintext"), rc4.rc4_crypt(b"Key2", b"Plaintext"))

    def test_each_operation_starts_fresh(self):
        self.assertEqual(rc4.rc4_crypt(b"Key", b"same"), rc4.rc4_crypt(b"Key", b"same"))

    def test_empty_key_is_rejected(self):
        with self.assertRaises(InputValidationError):
            rc4.ksa(b"")

    def test_oversized_key_is_rejected(self):
        with self.assertRaises(InputValidationError):
            rc4.ksa(bytes(257))

    def test_longest_and_shortest_keys_are_accepted(self):
        self.assertEqual(len(rc4.ksa(bytes(256))), 256)
        self.assertEqual(len(rc4.ksa(b"x")), 256)


class TraceTests(unittest.TestCase):
    PAYLOAD = {"algorithm": "rc4", "key": "Key", "plaintext": "Plaintext"}

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
        self.assertEqual(layout, [("init", 1), ("ksa", 256), ("ksa_done", 1), ("prga", 9), ("xor", 9)])
        self.assertEqual(len(steps), 276)
        for phase in summary["phases"]:
            for step in steps[phase["start"] : phase["start"] + phase["count"]]:
                self.assertEqual(step["phase"], phase["id"])

    def test_ksa_steps_match_the_algorithm(self):
        expected = []
        rc4.ksa(b"Key", expected.append)
        _, steps = self.all_steps()
        ksa_steps = [step for step in steps if step["phase"] == "ksa"]
        for step, truth in zip(ksa_steps, expected):
            self.assertEqual(step["S"], list(truth.state))
            self.assertEqual(step["j"], truth.j)
        self.assertEqual(ksa_steps[-1]["S"], rc4.ksa(b"Key"))

    def test_equation_uses_real_numbers(self):
        response = build_visualization({"algorithm": "rc4", "key": "010203", "key_encoding": "hex", "plaintext": "A", "start": 1, "count_steps": 1})
        self.assertEqual(response["steps"][0]["equation"], "j = (0 + 0 + 1) mod 256 = 1 mod 256 = 1")

    def test_trace_ciphertext_matches_direct_output(self):
        summary, steps = self.all_steps()
        self.assertEqual(summary["ciphertext_hex"], "BBF316E8D940AF0AD3")
        xor = [step for step in steps if step["phase"] == "xor"]
        self.assertEqual(bytes(step["ciphertext_byte"] for step in xor).hex().upper(), "BBF316E8D940AF0AD3")

    def test_prga_keystream_matches_direct_keystream(self):
        summary, steps = self.all_steps()
        prga = [step["keystream_byte"] for step in steps if step["phase"] == "prga"]
        self.assertEqual(bytes(prga), rc4.rc4_keystream(b"Key", 9))
        self.assertEqual(prga, summary["keystream"])

    def test_paging_gives_identical_snapshots(self):
        _, steps = self.all_steps()
        for index in (0, 1, 100, 257, 258, 275):
            single = build_visualization({**self.PAYLOAD, "start": index, "count_steps": 1})
            self.assertEqual(single["steps"][0], steps[index])

    def test_simplified_example_is_labelled_and_small(self):
        result = simplified_rc4({"key": [3, 1, 4]})
        self.assertIn("Not Standard RC4", result["label"])
        self.assertEqual(len(result["steps"]), 8)
        self.assertEqual(sorted(result["steps"][-1]["S"]), list(range(8)))


if __name__ == "__main__":
    unittest.main()
