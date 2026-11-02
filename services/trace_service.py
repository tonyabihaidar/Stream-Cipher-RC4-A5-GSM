"""Step-by-step traces for Visualization Mode.

Traces are built from the ``on_step`` callbacks of the real algorithms, so what is shown
is what the cipher did. Each step is a complete snapshot: going backwards just displays an
earlier snapshot, and nothing has to be undone.

The API is stateless. Each request recomputes the trace from its inputs and returns one
page of steps, which keeps payloads small and means no key is ever held on the server.
"""

from __future__ import annotations

from algorithms import a51, rc4
from algorithms.encoding_utils import (
    InputValidationError,
    bits_to_bytes,
    bits_to_string,
    bytes_to_bits,
    parse_int,
    to_base64,
    to_hex,
    unpack_bits,
)

from .cipher_service import ALGORITHM_NAMES, CipherParams, parse_params, parse_plaintext

MAX_TRACE_RC4_BYTES = 256
MAX_TRACE_A51_BYTES = 256
MAX_PAGE_STEPS = 128
DEFAULT_PAGE_STEPS = 64
MAX_SIMPLIFIED_KEY_VALUES = 8
SIMPLIFIED_SIZE = 8


def build_visualization(payload: dict) -> dict:
    """Validate a visualize request and return the requested page of the trace."""
    params = parse_params(payload)
    limit = MAX_TRACE_RC4_BYTES if params.algorithm == "rc4" else MAX_TRACE_A51_BYTES
    too_long = (
        f"Step-by-step traces are limited to {limit} bytes so they stay usable. Use Direct Mode for longer messages."
    )
    data, bit_length, _ = parse_plaintext(payload, params.algorithm, limit, too_long)

    if params.algorithm == "rc4":
        summary, steps = _rc4_trace(params, data)
    else:
        summary, steps = _a51_trace(params, data, bit_length, payload.get("segment"))

    start, count = _resolve_window(payload, summary["phases"], len(steps))
    response = {
        "algorithm": params.algorithm,
        "algorithm_name": ALGORITHM_NAMES[params.algorithm],
        "total_steps": len(steps),
        "range": {"start": start, "count": count},
        "steps": steps[start : start + count],
    }
    if payload.get("include_summary", True):
        response["summary"] = summary
    return response


def _resolve_window(payload: dict, phases: list[dict], total: int) -> tuple[int, int]:
    """Pick the page of steps: an absolute ``start``, or the start of a named ``phase``."""
    phase_id = payload.get("phase")
    default_start = 0
    if phase_id not in (None, ""):
        phase = next((item for item in phases if item["id"] == phase_id), None)
        if phase is None:
            names = ", ".join(item["id"] for item in phases)
            raise InputValidationError(f"Unknown phase. Available phases: {names}.", "phase")
        default_start = phase["start"]
    start_value = payload.get("start")
    start = default_start if start_value in (None, "") else parse_int(start_value, "start", "The start step", 0, total - 1)
    count_value = payload.get("count_steps")
    count = (
        DEFAULT_PAGE_STEPS
        if count_value in (None, "")
        else parse_int(count_value, "count_steps", "The requested step count", 1, MAX_PAGE_STEPS)
    )
    return start, min(count, total - start)


def _phases(entries: list[tuple[str, str, int, str]]) -> list[dict]:
    phases = []
    start = 0
    for phase_id, title, count, description in entries:
        phases.append({"id": phase_id, "title": title, "start": start, "count": count, "description": description})
        start += count
    return phases


def _byte_label(value: int) -> str:
    """A printable preview of a byte, for labels. Only ASCII is safe per-byte."""
    return chr(value) if 32 <= value < 127 else ""


# ---------------------------------------------------------------------------- RC4


def _rc4_trace(params: CipherParams, data: bytes) -> tuple[dict, list[dict]]:
    key = params.key
    steps: list[dict] = [
        {
            "phase": "init",
            "phase_step": 0,
            "S": list(range(rc4.STATE_SIZE)),
            "explanation": (
                "RC4 begins with an array containing all numbers from 0 to 255. "
                "KSA uses the secret key to rearrange these numbers."
            ),
        }
    ]

    def on_ksa(step: rc4.KsaStep) -> None:
        total = step.previous_j + step.s_i + step.key_byte
        same = step.i == step.j
        steps.append(
            {
                "phase": "ksa",
                "phase_step": step.iteration,
                "iteration": step.iteration,
                "i": step.i,
                "previous_j": step.previous_j,
                "key_index": step.key_index,
                "key_byte": step.key_byte,
                "s_i": step.s_i,
                "s_j": step.s_j,
                "j": step.j,
                "S": list(step.state),
                "equation": (
                    f"j = ({step.previous_j} + {step.s_i} + {step.key_byte}) mod 256 = {total} mod 256 = {step.j}"
                ),
                "explanation": (
                    f"Iteration {step.iteration + 1} of 256. Key byte {step.key_index} has the value {step.key_byte}, "
                    f"so j moves from {step.previous_j} to {step.j}. "
                    + (
                        f"i and j are both {step.i}, so this swap leaves the array unchanged."
                        if same
                        else f"S[{step.i}] = {step.s_i} and S[{step.j}] = {step.s_j} are swapped."
                    )
                ),
            }
        )

    state = rc4.ksa(key, on_ksa)
    steps.append(
        {
            "phase": "ksa_done",
            "phase_step": 0,
            "S": list(state),
            "explanation": (
                "KSA is complete. Every value from 0 to 255 is still present exactly once, but their order now depends "
                "on the key. PRGA starts from this permutation with i = 0 and j = 0."
            ),
        }
    )

    keystream: list[int] = []

    def on_prga(step: rc4.PrgaStep) -> None:
        keystream.append(step.keystream_byte)
        s_i_after, s_j_after = step.s_j, step.s_i
        steps.append(
            {
                "phase": "prga",
                "phase_step": step.index,
                "index": step.index,
                "previous_i": step.previous_i,
                "i": step.i,
                "previous_j": step.previous_j,
                "j": step.j,
                "s_i": step.s_i,
                "s_j": step.s_j,
                "s_i_after": s_i_after,
                "s_j_after": s_j_after,
                "t": step.t,
                "s_t": step.keystream_byte,
                "keystream_byte": step.keystream_byte,
                "S": list(step.state),
                "equations": {
                    "i": f"i = ({step.previous_i} + 1) mod 256 = {step.i}",
                    "j": f"j = ({step.previous_j} + {step.s_i}) mod 256 = {step.j}",
                    "t": (
                        f"t = (S[{step.i}] + S[{step.j}]) mod 256 = ({s_i_after} + {s_j_after}) mod 256 = {step.t}"
                    ),
                    "output": f"keystream[{step.index}] = S[{step.t}] = {step.keystream_byte}",
                },
                "explanation": (
                    f"Keystream byte {step.index + 1} of {len(data)}. The array is modified again: positions {step.i} "
                    f"and {step.j} are swapped, and the new S[{step.t}] = {step.keystream_byte} becomes the output."
                ),
            }
        )

    rc4.prga(state, len(data), on_prga)

    ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
    for index, (plain, ks, cipher) in enumerate(zip(data, keystream, ciphertext)):
        steps.append(
            {
                "phase": "xor",
                "phase_step": index,
                "index": index,
                "plaintext_byte": plain,
                "keystream_byte": ks,
                "ciphertext_byte": cipher,
                "plaintext_label": _byte_label(plain),
                "explanation": (
                    f"Byte {index + 1} of {len(data)}: {plain:08b} XOR {ks:08b} = {cipher:08b} "
                    f"(0x{plain:02X} XOR 0x{ks:02X} = 0x{cipher:02X})."
                ),
            }
        )

    summary = {
        "key_hex": to_hex(key),
        "key_bytes": list(key),
        "key_length": len(key),
        "plaintext_bytes": list(data),
        "plaintext_length": len(data),
        "keystream": keystream,
        "ciphertext_bytes": list(ciphertext),
        "ciphertext_hex": to_hex(ciphertext),
        "ciphertext_base64": to_base64(ciphertext),
        "phases": _phases(
            [
                ("init", "Initial array", 1, "The identity permutation S = [0, 1, ..., 255]."),
                ("ksa", "KSA", rc4.STATE_SIZE, "The key decides how the array is shuffled, over 256 iterations."),
                ("ksa_done", "Shuffled array", 1, "The permutation handed over to PRGA."),
                ("prga", "PRGA", len(data), "One keystream byte per plaintext byte, while the array keeps changing."),
                ("xor", "XOR", len(data), "Each plaintext byte is XORed with its keystream byte."),
            ]
        ),
    }
    return summary, steps


def simplified_rc4(payload: dict) -> dict:
    """The 8-element teaching example. It is deliberately not standard RC4."""
    raw = payload.get("key", [3, 1, 4])
    if not isinstance(raw, list) or not raw or len(raw) > MAX_SIMPLIFIED_KEY_VALUES:
        raise InputValidationError(
            f"Enter between 1 and {MAX_SIMPLIFIED_KEY_VALUES} key values for the simplified example.", "key"
        )
    key = [parse_int(value, "key", "Each key value", 0, 255) for value in raw]
    steps: list[dict] = []

    def on_step(step: rc4.KsaStep) -> None:
        total = step.previous_j + step.s_i + step.key_byte
        steps.append(
            {
                "i": step.i,
                "previous_j": step.previous_j,
                "key_byte": step.key_byte,
                "s_i": step.s_i,
                "s_j": step.s_j,
                "j": step.j,
                "S": list(step.state),
                "equation": (
                    f"j = ({step.previous_j} + {step.s_i} + {step.key_byte}) mod {SIMPLIFIED_SIZE} = {total} mod "
                    f"{SIMPLIFIED_SIZE} = {step.j}"
                ),
            }
        )

    rc4.simplified_ksa(key, SIMPLIFIED_SIZE, on_step)
    return {
        "label": "Simplified Teaching Example — Not Standard RC4",
        "size": SIMPLIFIED_SIZE,
        "key": key,
        "initial": list(range(SIMPLIFIED_SIZE)),
        "steps": steps,
    }


# --------------------------------------------------------------------------- A5/1


def _feedback_details(before: tuple[int, int, int], moved: tuple[bool, bool, bool]) -> list[dict]:
    """The XOR calculation for each register that actually advanced."""
    details = []
    for spec, value, advanced in zip(a51.REGISTERS, before, moved):
        if not advanced:
            continue
        taps = [{"bit": tap, "value": a51.get_bit(value, tap)} for tap in spec.taps]
        details.append(
            {
                "register": spec.name,
                "taps": taps,
                "expression": " ⊕ ".join(str(tap["value"]) for tap in taps),
                "result": a51.feedback_bit(value, spec),
            }
        )
    return details


def _moved_names(moved: tuple[bool, bool, bool], want: bool) -> list[str]:
    return [spec.name for spec, flag in zip(a51.REGISTERS, moved) if flag is want]


def _join_names(names: list[str]) -> str:
    return " and ".join(names) if len(names) < 3 else f"{names[0]}, {names[1]} and {names[2]}"


def _majority_sentence(step: a51.ClockStep) -> str:
    agreeing = sum(1 for bit in step.clock_bits if bit == step.majority)
    count_word = "all three registers have" if agreeing == 3 else "two registers have"
    advancing = _moved_names(step.moved, True)
    still = _moved_names(step.moved, False)
    sentence = f"The majority bit is {step.majority} because {count_word} a control bit equal to {step.majority}. "
    if still:
        sentence += f"Therefore, {_join_names(advancing)} advance while {still[0]} remains unchanged."
    else:
        sentence += "Therefore, all three registers advance."
    return sentence


def _clock_step_dict(step: a51.ClockStep) -> dict:
    return {
        "phase": step.phase,
        "phase_step": step.index,
        "registers_before": list(step.before),
        "registers_after_clock": list(step.after_clock),
        "registers": list(step.after),
        "clock_bits": list(step.clock_bits),
        "majority": step.majority,
        "moved": list(step.moved),
        "feedback": _feedback_details(step.before, step.moved),
        "output_bits": list(step.output_bits),
    }


def _a51_trace(params: CipherParams, data: bytes, bit_length: int, segment_value: object) -> tuple[dict, list[dict]]:
    key = params.key
    bits = unpack_bits(data, bit_length)
    result = a51.crypt_bits(key, bits, params.direction, params.start_count, params.start_fn)
    selected = 0
    if segment_value not in (None, ""):
        selected = parse_int(segment_value, "segment", "The segment number", 0, len(result.segments) - 1)
    traced_segment = result.segments[selected]

    steps: list[dict] = [
        {
            "phase": "clear",
            "phase_step": 0,
            "registers_before": [0, 0, 0],
            "registers_after_clock": [0, 0, 0],
            "registers": [0, 0, 0],
            "clock_bits": [0, 0, 0],
            "majority": None,
            "moved": [False, False, False],
            "feedback": [],
            "output_bits": [0, 0, 0],
            "explanation": (
                "All three registers start at zero. The key and COUNT are then mixed in one bit at a time."
            ),
        }
    ]
    init_state: list[int] = []
    downlink: list[int] = []
    uplink: list[int] = []

    def on_step(step: a51.ClockStep) -> None:
        item = _clock_step_dict(step)
        if step.phase == "key":
            byte_index, bit_index = step.index // 8, step.index % 8
            item.update(
                input_bit=step.input_bit,
                input_source=f"Kc bit {step.index} (byte {byte_index}, bit {bit_index}, LSB first)",
                explanation=(
                    f"Key bit {step.index + 1} of {a51.KEY_BITS}. All three registers clock without majority control, "
                    f"then the key bit {step.input_bit} is XORed into bit 0 of each register."
                ),
            )
        elif step.phase == "count":
            item.update(
                input_bit=step.input_bit,
                input_source=f"COUNT bit {step.index} (LSB first)",
                explanation=(
                    f"COUNT bit {step.index + 1} of {a51.COUNT_BITS}. All three registers clock without majority "
                    f"control, then the COUNT bit {step.input_bit} is XORed into bit 0 of each register."
                ),
            )
        elif step.phase == "warmup":
            item.update(
                counter=f"Warm-up cycle {step.index + 1} / {a51.WARMUP_CYCLES}",
                explanation=_majority_sentence(step) + " The output of this cycle is discarded.",
            )
        else:
            sequence = downlink if step.phase == "downlink" else uplink
            sequence.append(step.output)
            o1, o2, o3 = step.output_bits
            generated = len(downlink) + len(uplink)
            item.update(
                phase="keystream",
                sequence=step.phase,
                sequence_index=step.index,
                keystream_index=generated - 1,
                keystream_bit=step.output,
                generated=generated,
                counter=f"{step.phase.capitalize()} bit {step.index + 1} / {a51.SEQUENCE_BITS}",
                equation=f"{o1} ⊕ {o2} ⊕ {o3} = {step.output}",
                explanation=(
                    _majority_sentence(step)
                    + f" After clocking, the output bits are XORed to give keystream bit {step.output}."
                ),
            )
        steps.append(item)
        if step.phase == "count" and step.index == a51.COUNT_BITS - 1:
            init_state.extend(step.after)
            steps.append(
                {
                    "phase": "loaded",
                    "phase_step": 0,
                    "registers_before": list(step.after),
                    "registers_after_clock": list(step.after),
                    "registers": list(step.after),
                    "clock_bits": [a51.get_bit(v, s.clock_bit) for v, s in zip(step.after, a51.REGISTERS)],
                    "majority": None,
                    "moved": [False, False, False],
                    "feedback": [],
                    "output_bits": [a51.get_bit(v, s.output_bit) for v, s in zip(step.after, a51.REGISTERS)],
                    "explanation": (
                        f"Initialization is complete: {a51.KEY_BITS} key bits and {a51.COUNT_BITS} COUNT bits have been "
                        "loaded. From now on, registers advance only under majority control."
                    ),
                }
            )

    frame = a51.generate_frame(key, traced_segment.count, on_step)

    segments_summary = []
    position = 0
    for segment in result.segments:
        sequence = a51.generate_frame(key, segment.count).sequence(params.direction)
        plain = bits[segment.start_bit : segment.start_bit + segment.length]
        cipher = result.output[segment.start_bit : segment.start_bit + segment.length]
        segments_summary.append(
            {
                "index": segment.index,
                "count": segment.count,
                "count_hex": f"0x{segment.count:06X}",
                "fn": segment.fn,
                "start_bit": segment.start_bit,
                "length": segment.length,
                "generated": a51.SEQUENCE_BITS,
                "unused": a51.SEQUENCE_BITS - segment.length,
                "keystream_bits": bits_to_string(sequence),
                "plaintext_bits": bits_to_string(plain),
                "ciphertext_bits": bits_to_string(cipher),
            }
        )
        for offset in range(segment.length):
            p, k, c = plain[offset], sequence[offset], cipher[offset]
            new_frame = offset == 0 and segment.index > 0
            steps.append(
                {
                    "phase": "xor",
                    "phase_step": position,
                    "bit_index": position,
                    "segment": segment.index,
                    "segment_bit": offset,
                    "count": segment.count,
                    "plaintext_bit": p,
                    "keystream_bit": k,
                    "ciphertext_bit": c,
                    "explanation": (
                        (
                            f"Segment {segment.index + 1} begins. The cipher is reinitialized with the same key and "
                            f"COUNT 0x{segment.count:06X}, which gives a new 114-bit keystream. "
                            if new_frame
                            else ""
                        )
                        + f"Message bit {position + 1} of {bit_length}: {p} XOR {k} = {c}."
                    ),
                }
            )
            position += 1

    ciphertext = bits_to_bytes(result.output)
    t_values = None
    if params.count_mode == "fn":
        t1, t2, t3 = a51.fn_components(params.start_fn)
        t_values = {"fn": params.start_fn, "t1": t1, "t2": t2, "t3": t3}

    summary = {
        "key_hex": to_hex(key),
        "key_bits": [a51.key_bit(key, position) for position in range(a51.KEY_BITS)],
        "direction": params.direction,
        "count_mode": params.count_mode,
        "start_count": params.first_count,
        "start_count_hex": f"0x{params.first_count:06X}",
        "fn_details": t_values,
        "bit_length": bit_length,
        "plaintext_binary": bits_to_string(bits),
        "ciphertext_hex": to_hex(ciphertext),
        "ciphertext_base64": to_base64(ciphertext),
        "ciphertext_binary": bits_to_string(bytes_to_bits(ciphertext)[:bit_length]),
        "segment_count": len(result.segments),
        "selected_segment": selected,
        "traced_count": traced_segment.count,
        "traced_count_hex": f"0x{traced_segment.count:06X}",
        "segments": segments_summary,
        "downlink": bits_to_string(frame.downlink),
        "uplink": bits_to_string(frame.uplink),
        "initialized_registers": init_state,
        "registers": [
            {
                "name": spec.name,
                "length": spec.length,
                "taps": list(spec.taps),
                "clock_bit": spec.clock_bit,
                "output_bit": spec.output_bit,
            }
            for spec in a51.REGISTERS
        ],
        "phases": _phases(
            [
                ("clear", "Clear", 1, "All registers are set to zero."),
                ("key", "Load key", a51.KEY_BITS, "64 key bits, with every register clocked each time."),
                ("count", "Load COUNT", a51.COUNT_BITS, "22 COUNT bits, with every register clocked each time."),
                ("loaded", "Initialized", 1, "The register states after loading the key and COUNT."),
                ("warmup", "Warm-up", a51.WARMUP_CYCLES, "100 majority-clocked cycles with discarded output."),
                ("keystream", "Keystream", a51.FRAME_BITS, "228 bits: 114 downlink, then 114 uplink."),
                ("xor", "XOR", bit_length, "Each message bit is XORed with its keystream bit."),
            ]
        ),
    }
    return summary, steps
