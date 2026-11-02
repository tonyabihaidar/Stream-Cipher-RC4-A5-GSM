"""Request validation and the Direct Mode encrypt/decrypt operations.

Every function here is stateless: nothing is stored and keys are never logged. A key is
also never copied into a response or an exported record.
"""

from __future__ import annotations

from dataclasses import dataclass

from algorithms import a51, rc4
from algorithms.encoding_utils import (
    InputValidationError,
    bits_to_bytes,
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
from algorithms.xor_utils import xor_bytes

MAX_DIRECT_BYTES = 16 * 1024
MAX_SEGMENTS_RETURNED = 64
RECORD_TYPE = "eece455.stream-cipher.ciphertext"

ALGORITHM_NAMES = {"rc4": "RC4", "a51": "A5/1"}
_ALGORITHM_ALIASES = {"rc4": "rc4", "a51": "a51", "a5/1": "a51", "a5-1": "a51"}


@dataclass(frozen=True)
class CipherParams:
    """A validated algorithm selection, key and frame parameters."""

    algorithm: str
    key: bytes
    key_encoding: str
    direction: str | None = None
    count_mode: str | None = None
    start_count: int | None = None
    start_fn: int | None = None

    @property
    def first_count(self) -> int | None:
        """The COUNT actually used by the first frame, whichever mode supplied it."""
        if self.algorithm != "a51":
            return None
        return a51.fn_to_count(self.start_fn) if self.count_mode == "fn" else self.start_count


def _string_field(payload: dict, name: str, label: str, required: bool = True, default: str = "") -> str:
    value = payload.get(name)
    if value is None:
        if required:
            raise InputValidationError(f"{label} is required.", name)
        return default
    if not isinstance(value, str):
        raise InputValidationError(f"{label} must be text.", name)
    return value


def _choice_field(payload: dict, name: str, label: str, choices: tuple[str, ...], default: str) -> str:
    value = _string_field(payload, name, label, required=False, default=default)
    if value not in choices:
        raise InputValidationError(f"{label} must be one of: {', '.join(choices)}.", name)
    return value


def parse_algorithm(payload: dict) -> str:
    value = payload.get("algorithm")
    algorithm = _ALGORITHM_ALIASES.get(value.strip().lower()) if isinstance(value, str) else None
    if algorithm is None:
        raise InputValidationError("Algorithm must be either RC4 or A5/1.", "algorithm")
    return algorithm


def parse_params(payload: dict) -> CipherParams:
    """Validate the key and any algorithm-specific parameters."""
    algorithm = parse_algorithm(payload)
    if algorithm == "rc4":
        return _parse_rc4_params(payload)
    return _parse_a51_params(payload)


def _parse_rc4_params(payload: dict) -> CipherParams:
    encoding = _choice_field(payload, "key_encoding", "Key encoding", ("text", "hex"), "text")
    raw_key = _string_field(payload, "key", "The secret key", required=False)
    if not raw_key:
        raise InputValidationError("Enter a secret key. An RC4 key must contain between 1 and 256 bytes.", "key")
    if encoding == "hex":
        key = parse_hex(raw_key, "key", "A hexadecimal RC4 key")
    else:
        key = text_to_bytes(raw_key, "key")
    rc4.validate_key(key)
    return CipherParams("rc4", key, encoding)


def _parse_a51_params(payload: dict) -> CipherParams:
    raw_key = _string_field(payload, "key", "The secret key", required=False)
    cleaned = "".join(raw_key.split())
    if len(cleaned) != 16:
        raise InputValidationError("An A5/1 key must contain exactly 16 hexadecimal characters.", "key")
    key = parse_hex(cleaned, "key", "An A5/1 key")

    direction = _choice_field(payload, "direction", "Direction", a51.DIRECTIONS, a51.DOWNLINK)
    count_mode = _choice_field(payload, "count_mode", "Frame input mode", ("count", "fn"), "count")
    if count_mode == "fn":
        if payload.get("fn") in (None, ""):
            raise InputValidationError("Enter a TDMA frame number.", "fn")
        fn = parse_int(payload["fn"], "fn", "The TDMA frame number", 0, a51.MAX_FN)
        return CipherParams("a51", key, "hex", direction, count_mode, None, fn)

    if payload.get("count") in (None, ""):
        raise InputValidationError("Enter a 22-bit COUNT value.", "count")
    count = parse_int(payload["count"], "count", "COUNT", 0, a51.MAX_COUNT, f" (0x{a51.MAX_COUNT:X})")
    return CipherParams("a51", key, "hex", direction, count_mode, count, None)


def parse_plaintext(
    payload: dict, algorithm: str, max_bytes: int = MAX_DIRECT_BYTES, too_long_message: str | None = None
) -> tuple[bytes, int, str]:
    """Return (packed bytes, exact bit length, input format)."""
    fmt = _choice_field(payload, "input_format", "Input format", ("text", "hex", "binary"), "text")
    raw = _string_field(payload, "plaintext", "The plaintext", required=False)
    if raw == "" or (fmt != "text" and not raw.strip()):
        raise InputValidationError("Enter a message to process.", "plaintext")

    if fmt == "text":
        data = text_to_bytes(raw, "plaintext")
        bit_length = len(data) * 8
    elif fmt == "hex":
        data = parse_hex(raw, "plaintext", "Hexadecimal plaintext")
        bit_length = len(data) * 8
    else:
        bits = parse_binary(raw, "plaintext", "Binary plaintext")
        if algorithm == "rc4" and len(bits) % 8:
            raise InputValidationError("RC4 works on whole bytes, so binary input must be a multiple of 8 bits.",
                                       "plaintext")
        data = bits_to_bytes(bits)
        bit_length = len(bits)

    if bit_length == 0:
        raise InputValidationError("Enter a message to process.", "plaintext")
    if len(data) > max_bytes:
        message = too_long_message or f"The message is too long. The limit here is {max_bytes} bytes."
        raise InputValidationError(message, "plaintext")
    return data, bit_length, fmt


def parse_ciphertext(payload: dict, algorithm: str) -> tuple[bytes, int, str]:
    """Return (packed bytes, exact bit length, encoding)."""
    encoding = _choice_field(payload, "ciphertext_encoding", "Ciphertext format", ("hex", "base64"), "hex")
    raw = _string_field(payload, "ciphertext", "The ciphertext", required=False)
    if not raw.strip():
        raise InputValidationError("Enter the ciphertext to decrypt.", "ciphertext")
    if encoding == "hex":
        data = parse_hex(raw, "ciphertext", "Hexadecimal ciphertext")
    else:
        data = parse_base64(raw, "ciphertext", "The ciphertext")
    if not data:
        raise InputValidationError("Enter the ciphertext to decrypt.", "ciphertext")
    if len(data) > MAX_DIRECT_BYTES:
        raise InputValidationError(f"The ciphertext is too long. The limit here is {MAX_DIRECT_BYTES} bytes.",
                                   "ciphertext")
    return data, _ciphertext_bit_length(payload, data, algorithm), encoding


def _ciphertext_bit_length(payload: dict, data: bytes, algorithm: str) -> int:
    """Work out how many serialized bits are meaningful and check the padding is clean."""
    total = len(data) * 8
    raw = payload.get("bit_length")
    if raw in (None, ""):
        return total
    bit_length = parse_int(raw, "bit_length", "The meaningful bit length", 1, total, " for this ciphertext")
    if algorithm == "rc4" and bit_length != total:
        raise InputValidationError("RC4 ciphertext is always a whole number of bytes.", "bit_length")
    if bit_length <= total - 8:
        raise InputValidationError(
            f"A bit length of {bit_length} needs {(bit_length + 7) // 8} bytes, but the ciphertext has {len(data)}.",
            "bit_length",
        )
    if any(bytes_to_bits(data)[bit_length:]):
        raise InputValidationError(
            "The padding bits after the stated bit length are not zero. Check the ciphertext and its bit length.",
            "bit_length",
        )
    return bit_length


@dataclass(frozen=True)
class StreamOutput:
    output: bytes
    keystream: bytes
    bit_length: int
    bits_generated: int
    segments: list[a51.Segment] | None


def run_cipher(params: CipherParams, data: bytes, bit_length: int) -> StreamOutput:
    """Apply the keystream to the input. The same call encrypts and decrypts."""
    if params.algorithm == "rc4":
        keystream = rc4.rc4_keystream(params.key, len(data))
        return StreamOutput(xor_bytes(data, keystream), keystream, bit_length, bit_length, None)
    bits = unpack_bits(data, bit_length)
    result = a51.crypt_bits(params.key, bits, params.direction, params.start_count, params.start_fn)
    return StreamOutput(
        bits_to_bytes(result.output),
        bits_to_bytes(result.keystream),
        bit_length,
        len(result.segments) * a51.SEQUENCE_BITS,
        result.segments,
    )


def _serialized(data: bytes, bit_length: int) -> dict:
    return {
        "hex": to_hex(data),
        "base64": to_base64(data),
        "binary": to_binary(data)[:bit_length],
        "bit_length": bit_length,
        "byte_length": len(data),
        "padding_bits": len(data) * 8 - bit_length,
    }


def _parameters(params: CipherParams, key_length: int) -> dict:
    if params.algorithm == "rc4":
        return {"key_encoding": params.key_encoding, "key_length_bytes": key_length}
    result = {
        "key_length_bytes": key_length,
        "direction": params.direction,
        "count_mode": params.count_mode,
        "start_count": params.first_count,
        "start_count_hex": f"0x{params.first_count:06X}",
    }
    if params.count_mode == "fn":
        t1, t2, t3 = a51.fn_components(params.start_fn)
        result.update(start_fn=params.start_fn, t1=t1, t2=t2, t3=t3)
    return result


def _segment_details(stream: StreamOutput) -> dict:
    """Per-frame accounting for the UI. Detail is capped so huge inputs stay light."""
    segments = stream.segments or []
    return {
        "segment_count": len(segments),
        "segments_truncated": len(segments) > MAX_SEGMENTS_RETURNED,
        "segments": [
            {
                "index": segment.index,
                "count": segment.count,
                "count_hex": f"0x{segment.count:06X}",
                "fn": segment.fn,
                "start_bit": segment.start_bit,
                "keystream_generated": a51.SEQUENCE_BITS,
                "keystream_used": segment.length,
                "keystream_unused": a51.SEQUENCE_BITS - segment.length,
            }
            for segment in segments[:MAX_SEGMENTS_RETURNED]
        ],
    }


def _keystream_summary(stream: StreamOutput) -> dict:
    return {
        "hex": to_hex(stream.keystream),
        "binary": to_binary(stream.keystream)[: stream.bit_length],
        "bits_generated": stream.bits_generated,
        "bits_used": stream.bit_length,
        "bits_unused": stream.bits_generated - stream.bit_length,
    }


def build_record(params: CipherParams, ciphertext: bytes, bit_length: int, segment_count: int | None = None) -> dict:
    """A shareable description of a ciphertext. It deliberately omits the secret key."""
    record = {
        "record_type": RECORD_TYPE,
        "version": 1,
        "algorithm": params.algorithm,
        "encoding": "hex",
        "ciphertext": to_hex(ciphertext),
        "bit_length": bit_length,
    }
    if params.algorithm == "a51":
        record.update(
            direction=params.direction,
            count_mode=params.count_mode,
            start_count=params.first_count,
            start_fn=params.start_fn,
            segment_count=segment_count,
            count_advance="COUNT + 1 mod 2^22" if params.count_mode == "count" else "FN + 1 mod 2715648",
        )
    else:
        record["key_encoding"] = params.key_encoding
    return record


def _describe_rc4(operation: str, byte_length: int) -> str:
    verb = "encrypted" if operation == "encrypt" else "decrypted"
    return (
        f"KSA shuffled the 256-byte state using the key. PRGA then produced {byte_length} keystream "
        f"byte{'s' if byte_length != 1 else ''}, and each input byte was XORed with one keystream byte to give the "
        f"{verb} output. No padding was added."
    )


def _describe_a51(operation: str, stream: StreamOutput, direction: str) -> str:
    verb = "encrypted" if operation == "encrypt" else "decrypted"
    count = len(stream.segments)
    return (
        f"The 64-bit key and COUNT initialized three LFSRs, followed by 100 discarded warm-up cycles. "
        f"{count} frame{'s' if count != 1 else ''} generated {stream.bits_generated} {direction} keystream bits, of which "
        f"{stream.bit_length} were XORed with the input to give the {verb} output. "
        f"The remaining {stream.bits_generated - stream.bit_length} bits were not used, and no padding was added to "
        f"the message."
    )


def encrypt(payload: dict) -> dict:
    params = parse_params(payload)
    data, bit_length, fmt = parse_plaintext(payload, params.algorithm)
    stream = run_cipher(params, data, bit_length)
    plaintext = _serialized(data, bit_length)
    plaintext["text"] = payload["plaintext"] if fmt == "text" else None
    plaintext["format"] = fmt
    describe = (
        _describe_rc4("encrypt", len(data))
        if params.algorithm == "rc4"
        else _describe_a51("encrypt", stream, params.direction)
    )
    response = {
        "operation": "encrypt",
        "algorithm": params.algorithm,
        "algorithm_name": ALGORITHM_NAMES[params.algorithm],
        "plaintext": plaintext,
        "ciphertext": _serialized(stream.output, bit_length),
        "keystream": _keystream_summary(stream),
        "parameters": _parameters(params, len(params.key)),
        "relation": "Ciphertext = Plaintext XOR Keystream",
        "description": describe,
    }
    if params.algorithm == "a51":
        response.update(_segment_details(stream))
    response["record"] = build_record(params, stream.output, bit_length, response.get("segment_count"))
    return response


def decrypt(payload: dict) -> dict:
    params = parse_params(payload)
    data, bit_length, encoding = parse_ciphertext(payload, params.algorithm)
    stream = run_cipher(params, data, bit_length)
    recovered = _serialized(stream.output, bit_length)
    byte_aligned = bit_length % 8 == 0
    text = bytes_to_text(stream.output) if byte_aligned else None
    recovered["text"] = text
    recovered["utf8_valid"] = text is not None
    if not byte_aligned:
        recovered["message"] = (
            f"The output is {bit_length} bits, which is not a whole number of bytes, so it is shown as binary."
        )
    elif text is None:
        recovered["message"] = (
            "The recovered bytes are not valid UTF-8. The key or parameters may be wrong, or the original data may not "
            "have been text. Stream ciphers have no integrity check, so a wrong key produces garbage, not an error."
        )
    describe = (
        _describe_rc4("decrypt", len(data))
        if params.algorithm == "rc4"
        else _describe_a51("decrypt", stream, params.direction)
    )
    response = {
        "operation": "decrypt",
        "algorithm": params.algorithm,
        "algorithm_name": ALGORITHM_NAMES[params.algorithm],
        "ciphertext": {**_serialized(data, bit_length), "encoding": encoding},
        "recovered": recovered,
        "keystream": _keystream_summary(stream),
        "parameters": _parameters(params, len(params.key)),
        "relation": "Plaintext = Ciphertext XOR Keystream",
        "description": describe,
    }
    if params.algorithm == "a51":
        response.update(_segment_details(stream))
    return response

