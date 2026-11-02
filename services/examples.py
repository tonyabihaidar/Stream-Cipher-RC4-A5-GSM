"""One-click educational examples.

``expected`` values marked "published" come from reference material and are checked by the
test suite. Values marked "computed" are calculated here by the real implementation.
"""

from __future__ import annotations

from .cipher_service import encrypt

A51_REFERENCE_KEY = "1223456789ABCDEF"
ZEROS_114 = "0" * 114


def _rc4(example_id: str, label: str, description: str, *, key: str, key_encoding: str, plaintext: str,
         input_format: str = "text", published: str | None = None, reference: str | None = None) -> dict:
    return {
        "id": example_id,
        "algorithm": "rc4",
        "label": label,
        "description": description,
        "fields": {"key": key, "key_encoding": key_encoding, "plaintext": plaintext, "input_format": input_format},
        "published_ciphertext": published,
        "reference": reference,
    }


def _a51(example_id: str, label: str, description: str, *, plaintext: str, key: str = A51_REFERENCE_KEY,
         count: str = "0x134", fn: str | None = None, direction: str = "downlink", input_format: str = "text",
         published: str | None = None, reference: str | None = None) -> dict:
    fields = {
        "key": key,
        "direction": direction,
        "plaintext": plaintext,
        "input_format": input_format,
        "count_mode": "fn" if fn is not None else "count",
        "count": "" if fn is not None else count,
        "fn": fn if fn is not None else "",
    }
    return {
        "id": example_id,
        "algorithm": "a51",
        "label": label,
        "description": description,
        "fields": fields,
        "published_ciphertext": published,
        "reference": reference,
    }


def get_examples() -> list[dict]:
    examples = [
        _rc4("rc4-key-plaintext", "Key / Plaintext (published vector)",
             "The widely published RC4 example.",
             key="Key", key_encoding="text", plaintext="Plaintext", published="BBF316E8D940AF0AD3",
             reference="Common RC4 test vector"),
        _rc4("rc4-rfc6229", "RFC 6229, 40-bit key",
             "Encrypting 16 zero bytes reveals the first 16 keystream bytes.",
             key="0102030405", key_encoding="hex", plaintext="00" * 16, input_format="hex",
             published="B2396305F03DC027CCC3524A0A1118A8", reference="RFC 6229"),
        _rc4("rc4-hello", "Hello World", "A short ASCII message.",
             key="Secret", key_encoding="text", plaintext="Hello World"),
        _rc4("rc4-arabic", "Arabic text (Unicode)",
             "Arabic letters take two bytes each in UTF-8, so bytes and characters differ.",
             key="Secret", key_encoding="text", plaintext="مرحبا بالعالم"),
        _a51("a51-reference-downlink", "Reference vector, downlink (114 bits)",
             "114 zero bits, so the ciphertext equals the published keystream.",
             plaintext=ZEROS_114, input_format="binary", published="534EAA582FE8151AB6E1855A728C00",
             reference="Briceno, Goldberg and Wagner reference code"),
        _a51("a51-reference-uplink", "Reference vector, uplink (114 bits)",
             "The second published 114-bit sequence for the same key and COUNT.",
             plaintext=ZEROS_114, input_format="binary", direction="uplink",
             published="24FD35A35D5FB6526D32F906DF1AC0",
             reference="Briceno, Goldberg and Wagner reference code"),
        _a51("a51-osmocom-fn", "TDMA frame number 123456",
             "An Osmocom test vector, using FN input. Osmocom stores the key bytes in reverse order.",
             plaintext=ZEROS_114, input_format="binary", key="EFCDAB8967452301", fn="123456",
             published="CBA25576175D3B1C7B2F29A8C1B600", reference="libosmocore tests/a5/a5_test.c"),
        _a51("a51-hi", "HI (short message)", "16 bits of message: 98 of the 114 keystream bits go unused.",
             plaintext="HI"),
        _a51("a51-hello-gsm", "Hello GSM", "72 bits of message, still inside one frame.", plaintext="Hello GSM"),
        _a51("a51-multiframe", "Multi-frame message",
             "This message is longer than 114 bits, so it spans several educational frames.",
             plaintext="A5/1 produces 114 bits per frame, so this message needs several frames."),
    ]
    for example in examples:
        result = encrypt({"algorithm": example["algorithm"], **example["fields"]})
        example["expected_ciphertext"] = result["ciphertext"]["hex"]
        example["expected_source"] = "published" if example["published_ciphertext"] else "computed"
    return examples
