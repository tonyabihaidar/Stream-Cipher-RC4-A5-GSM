"""Integration tests for the Flask endpoints and the schema the frontend relies on."""

import json
import logging
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app
from services.cipher_service import RECORD_TYPE

RC4_FIELDS = {"algorithm": "rc4", "key": "Key", "key_encoding": "text"}
A51_FIELDS = {
    "algorithm": "a51",
    "key": "1223456789ABCDEF",
    "count_mode": "count",
    "count": "0x134",
    "fn": "",
    "direction": "downlink",
}


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def post(self, path, payload):
        return self.client.post(path, json=payload)

    def assert_error(self, response, status, field=None, contains=None):
        self.assertEqual(response.status_code, status, response.get_data(as_text=True))
        error = response.get_json()["error"]
        self.assertTrue(error["message"])
        if field:
            self.assertEqual(error["field"], field)
        if contains:
            self.assertIn(contains, error["message"])


class BasicRouteTests(ApiTestCase):
    def test_index(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Stream Cipher Laboratory", response.get_data(as_text=True))

    def test_health(self):
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "ok")

    def test_static_modules_have_a_javascript_mime_type(self):
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("javascript", response.content_type)
        response.close()

    def test_unknown_route_returns_json(self):
        self.assert_error(self.client.get("/api/nope"), 404)

    def test_wrong_method(self):
        self.assert_error(self.client.get("/api/encrypt"), 405)


class Rc4ApiTests(ApiTestCase):
    def test_published_vector(self):
        result = self.post("/api/encrypt", {**RC4_FIELDS, "plaintext": "Plaintext"}).get_json()
        self.assertEqual(result["ciphertext"]["hex"], "BBF316E8D940AF0AD3")
        self.assertEqual(result["plaintext"]["byte_length"], 9)
        self.assertEqual(result["plaintext"]["bit_length"], 72)
        self.assertEqual(result["relation"], "Ciphertext = Plaintext XOR Keystream")

    def test_hex_key_and_hex_input(self):
        result = self.post(
            "/api/encrypt",
            {"algorithm": "rc4", "key": "0102030405", "key_encoding": "hex", "plaintext": "00" * 16, "input_format": "hex"},
        ).get_json()
        self.assertEqual(result["keystream"]["hex"], "B2396305F03DC027CCC3524A0A1118A8")
        self.assertEqual(result["ciphertext"]["hex"], result["keystream"]["hex"])

    def test_round_trip_keeps_text_exactly(self):
        for text in ("A", "  Spaces, Punctuation! 123  ", "مرحبا بالعالم", "Grüße 你好 🙂", "line\nbreak"):
            with self.subTest(text=text):
                encrypted = self.post("/api/encrypt", {**RC4_FIELDS, "plaintext": text}).get_json()
                for encoding in ("hex", "base64"):
                    decrypted = self.post(
                        "/api/decrypt",
                        {**RC4_FIELDS, "ciphertext": encrypted["ciphertext"][encoding], "ciphertext_encoding": encoding},
                    ).get_json()
                    self.assertEqual(decrypted["recovered"]["text"], text)
                    self.assertEqual(decrypted["relation"], "Plaintext = Ciphertext XOR Keystream")

    def test_wrong_key_shows_bytes_instead_of_failing(self):
        encrypted = self.post("/api/encrypt", {**RC4_FIELDS, "plaintext": "Plaintext"}).get_json()
        response = self.post("/api/decrypt", {"algorithm": "rc4", "key": "Wrong", "ciphertext": encrypted["ciphertext"]["hex"]})
        self.assertEqual(response.status_code, 200)
        recovered = response.get_json()["recovered"]
        self.assertFalse(recovered["utf8_valid"])
        self.assertIsNone(recovered["text"])
        self.assertTrue(recovered["hex"])
        self.assertIn("not valid UTF-8", recovered["message"])

    def test_validation(self):
        cases = [
            ({**RC4_FIELDS, "key": "", "plaintext": "x"}, "key"),
            ({**RC4_FIELDS, "key": "a" * 257, "plaintext": "x"}, "key"),
            ({"algorithm": "rc4", "key": "xyz", "key_encoding": "hex", "plaintext": "x"}, "key"),
            ({"algorithm": "rc4", "key": "abc", "key_encoding": "hex", "plaintext": "x"}, "key"),
            ({**RC4_FIELDS, "key_encoding": "morse", "plaintext": "x"}, "key_encoding"),
            ({**RC4_FIELDS, "plaintext": ""}, "plaintext"),
            ({**RC4_FIELDS, "plaintext": 5}, "plaintext"),
            ({**RC4_FIELDS, "plaintext": "101", "input_format": "binary"}, "plaintext"),
            ({**RC4_FIELDS, "plaintext": "x" * 16385}, "plaintext"),
            ({"key": "Key", "plaintext": "x"}, "algorithm"),
            ({"algorithm": "des", "key": "Key", "plaintext": "x"}, "algorithm"),
        ]
        for payload, field in cases:
            with self.subTest(field=field, payload=str(payload)[:60]):
                self.assert_error(self.post("/api/encrypt", payload), 400, field)

    def test_lone_surrogate_in_json_is_a_clean_error(self):
        # A JSON escape is the only way a lone surrogate can reach the server.
        body = '{"algorithm": "rc4", "key": "Key", "plaintext": "\\ud800"}'
        response = self.client.post("/api/encrypt", data=body, content_type="application/json")
        self.assert_error(response, 400, "plaintext")

    def test_ciphertext_validation(self):
        cases = [
            ({"ciphertext": ""}, "ciphertext"),
            ({"ciphertext": "zz"}, "ciphertext"),
            ({"ciphertext": "abc"}, "ciphertext"),
            ({"ciphertext": "a!b", "ciphertext_encoding": "base64"}, "ciphertext"),
            ({"ciphertext": "QUJD=", "ciphertext_encoding": "base64"}, "ciphertext"),
            ({"ciphertext": "AB", "ciphertext_encoding": "rot13"}, "ciphertext_encoding"),
            ({"ciphertext": "AB", "bit_length": 5}, "bit_length"),
        ]
        for extra, field in cases:
            with self.subTest(extra=extra):
                self.assert_error(self.post("/api/decrypt", {**RC4_FIELDS, **extra}), 400, field)


class A51ApiTests(ApiTestCase):
    def test_reference_vectors(self):
        for direction, expected in (("downlink", "534EAA582FE8151AB6E1855A728C00"), ("uplink", "24FD35A35D5FB6526D32F906DF1AC0")):
            result = self.post(
                "/api/encrypt",
                {**A51_FIELDS, "direction": direction, "plaintext": "0" * 114, "input_format": "binary"},
            ).get_json()
            self.assertEqual(result["ciphertext"]["hex"], expected)
            self.assertEqual(result["ciphertext"]["bit_length"], 114)
            self.assertEqual(result["ciphertext"]["padding_bits"], 6)
            self.assertEqual(result["keystream"]["bits_unused"], 0)

    def test_short_message_accounting(self):
        result = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": "HI"}).get_json()
        self.assertEqual(result["segment_count"], 1)
        self.assertEqual(result["keystream"]["bits_generated"], 114)
        self.assertEqual(result["keystream"]["bits_used"], 16)
        self.assertEqual(result["keystream"]["bits_unused"], 98)
        self.assertEqual(result["ciphertext"]["byte_length"], 2)

    def test_multi_frame_accounting(self):
        result = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": "x" * 25}).get_json()
        self.assertEqual(result["segment_count"], 2)
        first, second = result["segments"]
        self.assertEqual((first["count"], first["keystream_used"]), (0x134, 114))
        self.assertEqual((second["count"], second["keystream_used"], second["keystream_unused"]), (0x135, 86, 28))

    def test_round_trip_all_lengths(self):
        for text in ("H", "HI", "Hello GSM", "مرحبا بالعالم", "x" * 14, "x" * 15, "x" * 100, "ab" * 500):
            with self.subTest(length=len(text)):
                encrypted = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": text}).get_json()
                decrypted = self.post("/api/decrypt", {**A51_FIELDS, "ciphertext": encrypted["ciphertext"]["base64"], "ciphertext_encoding": "base64"}).get_json()
                self.assertEqual(decrypted["recovered"]["text"], text)

    def test_non_byte_aligned_round_trip(self):
        bits = "1011001110001"
        encrypted = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": bits, "input_format": "binary"}).get_json()
        self.assertEqual(encrypted["ciphertext"]["bit_length"], 13)
        self.assertEqual(encrypted["ciphertext"]["padding_bits"], 3)
        self.assertEqual(encrypted["record"]["bit_length"], 13)
        decrypted = self.post("/api/decrypt", {**A51_FIELDS, "ciphertext": encrypted["ciphertext"]["hex"], "bit_length": 13}).get_json()
        self.assertEqual(decrypted["recovered"]["binary"], bits)
        self.assertFalse(decrypted["recovered"]["utf8_valid"])
        self.assertIn("not a whole number of bytes", decrypted["recovered"]["message"])

    def test_dirty_padding_is_rejected(self):
        self.assert_error(self.post("/api/decrypt", {**A51_FIELDS, "ciphertext": "FF", "bit_length": 4}), 400, "bit_length")

    def test_bit_length_must_fit_the_ciphertext(self):
        self.assert_error(self.post("/api/decrypt", {**A51_FIELDS, "ciphertext": "0000", "bit_length": 3}), 400, "bit_length")
        self.assert_error(self.post("/api/decrypt", {**A51_FIELDS, "ciphertext": "00", "bit_length": 9}), 400, "bit_length")

    def test_directions_differ_and_must_match_to_decrypt(self):
        encrypted = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": "Hello GSM"}).get_json()
        wrong = self.post("/api/decrypt", {**A51_FIELDS, "direction": "uplink", "ciphertext": encrypted["ciphertext"]["hex"]}).get_json()
        self.assertNotEqual(wrong["recovered"]["text"], "Hello GSM")

    def test_fn_mode(self):
        result = self.post(
            "/api/encrypt",
            {"algorithm": "a51", "key": "EFCDAB8967452301", "count_mode": "fn", "fn": "123456", "plaintext": "0" * 114, "input_format": "binary"},
        ).get_json()
        self.assertEqual(result["ciphertext"]["hex"], "CBA25576175D3B1C7B2F29A8C1B600")
        self.assertEqual(result["parameters"]["start_fn"], 123456)
        self.assertEqual(result["parameters"]["start_count"], 0x2EC88)
        self.assertEqual(result["record"]["start_fn"], 123456)

    def test_validation(self):
        cases = [
            ({**A51_FIELDS, "key": "1234", "plaintext": "x"}, "key", "exactly 16 hexadecimal characters"),
            ({**A51_FIELDS, "key": "ZZ23456789ABCDEF", "plaintext": "x"}, "key", None),
            ({**A51_FIELDS, "key": "", "plaintext": "x"}, "key", None),
            ({**A51_FIELDS, "count": "", "plaintext": "x"}, "count", None),
            ({**A51_FIELDS, "count": "0x400000", "plaintext": "x"}, "count", None),
            ({**A51_FIELDS, "count": "-1", "plaintext": "x"}, "count", None),
            ({**A51_FIELDS, "count": "abc", "plaintext": "x"}, "count", None),
            ({**A51_FIELDS, "count": True, "plaintext": "x"}, "count", None),
            ({**A51_FIELDS, "count_mode": "fn", "fn": "", "plaintext": "x"}, "fn", None),
            ({**A51_FIELDS, "count_mode": "fn", "fn": "2715648", "plaintext": "x"}, "fn", None),
            ({**A51_FIELDS, "direction": "up", "plaintext": "x"}, "direction", None),
            ({**A51_FIELDS, "plaintext": ""}, "plaintext", None),
            ({**A51_FIELDS, "plaintext": "012", "input_format": "binary"}, "plaintext", None),
        ]
        for payload, field, message in cases:
            with self.subTest(payload=str(payload)[:90]):
                self.assert_error(self.post("/api/encrypt", payload), 400, field, message)


class RecordTests(ApiTestCase):
    def test_a51_record_contents(self):
        record = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": "x" * 25}).get_json()["record"]
        self.assertEqual(record["record_type"], RECORD_TYPE)
        self.assertEqual(record["algorithm"], "a51")
        self.assertEqual(record["direction"], "downlink")
        self.assertEqual(record["start_count"], 0x134)
        self.assertEqual(record["bit_length"], 200)
        self.assertEqual(record["encoding"], "hex")
        self.assertEqual(record["segment_count"], 2)

    def test_record_never_contains_the_key(self):
        secret_hex = "1223456789ABCDEF"
        record = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": "HI"}).get_json()["record"]
        self.assertNotIn(secret_hex, json.dumps(record))
        self.assertNotIn("key", {name for name in record if name != "key_encoding"})
        record = self.post("/api/encrypt", {"algorithm": "rc4", "key": "TopSecretKey", "plaintext": "HI"}).get_json()["record"]
        self.assertNotIn("TopSecretKey", json.dumps(record))

    def test_responses_never_echo_the_key(self):
        for payload in ({"algorithm": "rc4", "key": "TopSecretKey", "plaintext": "HI"}, {**A51_FIELDS, "plaintext": "HI"}):
            secret = payload["key"]
            body = self.post("/api/encrypt", payload).get_data(as_text=True)
            self.assertNotIn(secret, body)


class VisualizeApiTests(ApiTestCase):
    def test_direct_and_visualization_agree(self):
        cases = [
            {**RC4_FIELDS, "plaintext": "Hello World"},
            {**RC4_FIELDS, "plaintext": "مرحبا"},
            {**A51_FIELDS, "plaintext": "HI"},
            {**A51_FIELDS, "plaintext": "A long message spanning several frames of A5/1."},
            {**A51_FIELDS, "direction": "uplink", "plaintext": "Hello GSM"},
        ]
        for payload in cases:
            with self.subTest(payload=str(payload)[:60]):
                direct = self.post("/api/encrypt", payload).get_json()
                trace = self.post("/api/visualize", payload).get_json()
                self.assertEqual(trace["summary"]["ciphertext_hex"], direct["ciphertext"]["hex"])

    def test_every_page_is_served_without_summary_when_asked(self):
        page = self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "A", "start": 64, "count_steps": 64, "include_summary": False}).get_json()
        self.assertNotIn("summary", page)
        self.assertEqual(page["range"], {"start": 64, "count": 64})
        self.assertEqual(len(page["steps"]), 64)

    def test_phase_retrieval(self):
        page = self.post("/api/visualize", {**A51_FIELDS, "plaintext": "HI", "phase": "keystream", "count_steps": 2}).get_json()
        self.assertEqual([step["phase"] for step in page["steps"]], ["keystream", "keystream"])

    def test_page_size_is_limited(self):
        self.assert_error(self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "A", "count_steps": 500}), 400, "count_steps")

    def test_trace_message_size_is_limited(self):
        self.assert_error(self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "x" * 257}), 400, "plaintext", "Direct Mode")
        self.assert_error(self.post("/api/visualize", {**A51_FIELDS, "plaintext": "x" * 257}), 400, "plaintext", "Direct Mode")

    def test_trace_window_validation(self):
        self.assert_error(self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "A", "phase": "nope"}), 400, "phase")
        self.assert_error(self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "A", "start": 100000}), 400, "start")
        self.assert_error(self.post("/api/visualize", {**A51_FIELDS, "plaintext": "A", "segment": 3}), 400, "segment")

    def test_trace_payload_stays_reasonable(self):
        response = self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "x" * 256, "start": 0, "count_steps": 64})
        self.assertLess(len(response.get_data()), 200_000)

    def test_simplified_endpoint(self):
        result = self.post("/api/simplified-rc4", {"key": ["3", "1", "4"]}).get_json()
        self.assertEqual(result["key"], [3, 1, 4])
        self.assert_error(self.post("/api/simplified-rc4", {"key": []}), 400, "key")
        self.assert_error(self.post("/api/simplified-rc4", {"key": ["x"]}), 400, "key")


class RobustnessTests(ApiTestCase):
    def test_malformed_json(self):
        self.assert_error(self.client.post("/api/encrypt", data="{bad", content_type="application/json"), 400)

    def test_wrong_content_type(self):
        self.assert_error(self.client.post("/api/encrypt", data="x=1", content_type="text/plain"), 415)

    def test_body_must_be_an_object(self):
        self.assert_error(self.post("/api/encrypt", [1, 2, 3]), 400)

    def test_oversized_request(self):
        self.assert_error(self.post("/api/encrypt", {**RC4_FIELDS, "plaintext": "x" * (2 * 1024 * 1024)}), 413)

    def test_unexpected_errors_do_not_leak_details(self):
        app = create_app()
        app.config["PROPAGATE_EXCEPTIONS"] = False

        @app.get("/api/explode")
        def explode():
            raise RuntimeError("secret internal detail")

        logging.disable(logging.CRITICAL)
        try:
            response = app.test_client().get("/api/explode")
        finally:
            logging.disable(logging.NOTSET)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret internal detail", response.get_data(as_text=True))

    def test_keys_are_not_logged(self):
        with self.assertLogs(level="DEBUG") as captured:
            logging.getLogger("probe").debug("start")
            self.post("/api/encrypt", {"algorithm": "rc4", "key": "TopSecretKey", "plaintext": "HI"})
        self.assertNotIn("TopSecretKey", "\n".join(captured.output))


class ExampleTests(ApiTestCase):
    def test_published_examples_reproduce_their_vectors(self):
        examples = self.client.get("/api/examples").get_json()["examples"]
        self.assertTrue(any(item["algorithm"] == "rc4" for item in examples))
        self.assertTrue(any(item["algorithm"] == "a51" for item in examples))
        for example in examples:
            with self.subTest(example=example["id"]):
                result = self.post("/api/encrypt", {"algorithm": example["algorithm"], **example["fields"]}).get_json()
                self.assertEqual(result["ciphertext"]["hex"], example["expected_ciphertext"])
                if example["published_ciphertext"]:
                    self.assertEqual(result["ciphertext"]["hex"], example["published_ciphertext"])

    def test_required_examples_exist(self):
        ids = {item["id"] for item in self.client.get("/api/examples").get_json()["examples"]}
        self.assertLessEqual(
            {"rc4-key-plaintext", "rc4-rfc6229", "rc4-hello", "a51-reference-downlink", "a51-hi", "a51-hello-gsm", "a51-multiframe"},
            ids,
        )

    def test_multiframe_example_spans_frames(self):
        examples = {item["id"]: item for item in self.client.get("/api/examples").get_json()["examples"]}
        example = examples["a51-multiframe"]
        result = self.post("/api/encrypt", {"algorithm": "a51", **example["fields"]}).get_json()
        self.assertGreater(result["segment_count"], 1)


class FrontendContractTests(ApiTestCase):
    """The JavaScript has no test runner here, so check its contract with the backend statically."""

    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_fields_read_by_direct_mode_exist_in_responses(self):
        script = self.read("static/js/direct_mode.js")
        encrypted = self.post("/api/encrypt", {**A51_FIELDS, "plaintext": "HI"}).get_json()
        decrypted = self.post("/api/decrypt", {**A51_FIELDS, "ciphertext": encrypted["ciphertext"]["hex"]}).get_json()
        for top, sub in re.findall(r"result\.(plaintext|ciphertext|keystream)\.(\w+)", script):
            self.assertTrue(sub in (encrypted.get(top) or {}) or sub in (decrypted.get(top) or {}), f"{top}.{sub}")
        # "message" is only present when the output cannot be shown as text, so use a wrong key.
        garbled = self.post("/api/decrypt", {**A51_FIELDS, "key": "0000000000000000", "ciphertext": encrypted["ciphertext"]["hex"]}).get_json()
        for sub in re.findall(r"\brecovered\.(\w+)", script):
            self.assertIn(sub, garbled["recovered"])

    def test_form_controls_used_by_scripts_exist_in_the_page(self):
        page = self.client.get("/").get_data(as_text=True)
        for name in ("rc4_key", "key_encoding", "a51_key", "count_mode", "count", "fn", "direction", "plaintext", "input_format", "ciphertext", "ciphertext_encoding", "bit_length"):
            self.assertIn(f'name="{name}"', page)
        for script in ("step_controls.js", "visualization_mode.js", "direct_mode.js"):
            for element_id in re.findall(r'getElementById\("([\w-]+)"\)', self.read(f"static/js/{script}")):
                self.assertIn(f'id="{element_id}"', page, f"{script}: {element_id}")

    def test_no_external_resources(self):
        page = self.client.get("/").get_data(as_text=True)
        self.assertNotRegex(page, r'(src|href)="https?://')
        for path in (ROOT / "static").rglob("*"):
            if path.suffix in (".js", ".css"):
                self.assertNotRegex(path.read_text(encoding="utf-8"), r'(import|url\()\s*["\']?https?://')

    def test_trace_fields_used_by_the_views_exist(self):
        rc4 = self.post("/api/visualize", {**RC4_FIELDS, "plaintext": "A", "start": 0, "count_steps": 128}).get_json()
        a51 = self.post("/api/visualize", {**A51_FIELDS, "plaintext": "A", "start": 0, "count_steps": 128}).get_json()
        for name in ("key_bytes", "keystream", "ciphertext_bytes", "plaintext_length", "ciphertext_hex"):
            self.assertIn(name, rc4["summary"])
        for name in ("registers", "segments", "downlink", "uplink", "direction", "selected_segment", "bit_length"):
            self.assertIn(name, a51["summary"])
        self.assertEqual(a51["summary"]["registers"][0]["taps"], [13, 16, 17, 18])


if __name__ == "__main__":
    unittest.main()
