"""A5/1, the original GSM stream cipher, following the Briceno-Goldberg-Wagner reference.

A5/1 has three linear feedback shift registers with 64 bits of state in total. Bit 0 is
the least significant bit of each register. A register clock shifts left by one, drops
the top bit and inserts the XOR of the tap bits at position 0.

One 228-bit frame is produced as follows:

1. Clear the registers.
2. Load the 64 key bits: clock all registers, then XOR the bit into bit 0 of each.
   Key bytes are used in written order, and each byte is read least significant bit first.
3. Load the 22 COUNT bits the same way, least significant bit first.
4. Run 100 majority-clocked cycles and discard the output.
5. Run 228 majority-clocked cycles. After each clock the output is
   R1[18] ^ R2[21] ^ R3[22]. The first 114 bits are downlink, the next 114 are uplink.

Key representation
------------------
The key used here matches the reference C code and the classic test vector, for example
``12 23 45 67 89 AB CD EF``. Osmocom's libosmocore reads ``key[7 - (i >> 3)]``, so it holds
the same key with the bytes reversed: ``EF CD AB 89 67 45 23 12``.

Long messages
-------------
GSM only ever produces 114 bits per direction per frame, and encrypts fixed radio bursts.
This application treats a message as a bit stream instead, and defines an *educational*
convention for longer input: each segment of up to 114 bits uses a fresh frame, with
COUNT advancing by 1 modulo 2^22. When a real TDMA frame number is supplied, FN advances
by 1 modulo 2715648 and each COUNT is derived from its FN. See ``build_segments``.

A5/1 is broken and is implemented here for education only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .encoding_utils import InputValidationError

KEY_BYTES = 8
KEY_BITS = 64
COUNT_BITS = 22
COUNT_MODULUS = 1 << COUNT_BITS
MAX_COUNT = COUNT_MODULUS - 1
WARMUP_CYCLES = 100
SEQUENCE_BITS = 114
FRAME_BITS = 2 * SEQUENCE_BITS

# GSM hyperframe: 26 x 51 x 2048 TDMA frames.
FN_MODULUS = 26 * 51 * 2048
MAX_FN = FN_MODULUS - 1

DOWNLINK = "downlink"
UPLINK = "uplink"
DIRECTIONS = (DOWNLINK, UPLINK)


@dataclass(frozen=True)
class RegisterSpec:
    name: str
    length: int
    taps: tuple[int, ...]
    clock_bit: int
    output_bit: int

    @property
    def mask(self) -> int:
        return (1 << self.length) - 1

    @property
    def tap_mask(self) -> int:
        mask = 0
        for tap in self.taps:
            mask |= 1 << tap
        return mask


R1 = RegisterSpec("R1", 19, (13, 16, 17, 18), 8, 18)
R2 = RegisterSpec("R2", 22, (20, 21), 10, 21)
R3 = RegisterSpec("R3", 23, (7, 20, 21, 22), 10, 22)
REGISTERS = (R1, R2, R3)


@dataclass(frozen=True)
class ClockStep:
    """Everything that happened during one clock cycle.

    ``before``, ``after_clock`` and ``after`` hold the three register values before the
    clock, after the shift, and after the input bit (if any) was XORed into bit 0.
    ``majority`` is None for the forced clocks used while loading the key and COUNT.
    """

    phase: str
    index: int
    input_bit: int | None
    before: tuple[int, int, int]
    after_clock: tuple[int, int, int]
    after: tuple[int, int, int]
    clock_bits: tuple[int, int, int]
    majority: int | None
    moved: tuple[bool, bool, bool]
    output_bits: tuple[int, int, int]
    output: int


@dataclass(frozen=True)
class Frame:
    downlink: list[int]
    uplink: list[int]

    def sequence(self, direction: str) -> list[int]:
        return self.downlink if direction == DOWNLINK else self.uplink


@dataclass(frozen=True)
class Segment:
    """Part of a message handled by one frame."""

    index: int
    start_bit: int
    length: int
    count: int
    fn: int | None


@dataclass(frozen=True)
class CryptResult:
    output: list[int]
    keystream: list[int]
    segments: list[Segment]


def parity(value: int) -> int:
    """XOR of all the bits of ``value``."""
    return bin(value).count("1") & 1


def get_bit(value: int, position: int) -> int:
    return (value >> position) & 1


def majority(a: int, b: int, c: int) -> int:
    """The value held by at least two of the three bits."""
    return 1 if a + b + c >= 2 else 0


def feedback_bit(value: int, spec: RegisterSpec) -> int:
    return parity(value & spec.tap_mask)


def clock_register(value: int, spec: RegisterSpec) -> int:
    """Shift one register left, keeping it inside its mask, and insert the feedback bit."""
    return ((value << 1) & spec.mask) | feedback_bit(value, spec)


def validate_key(key: bytes, field: str | None = "key") -> None:
    if len(key) != KEY_BYTES:
        raise InputValidationError("An A5/1 key must contain exactly 16 hexadecimal characters.", field)


def validate_count(count: int, field: str | None = "count") -> None:
    if not 0 <= count <= MAX_COUNT:
        raise InputValidationError(f"COUNT must be a 22-bit value between 0 and 0x{MAX_COUNT:X}.", field)


def validate_direction(direction: str, field: str | None = "direction") -> None:
    if direction not in DIRECTIONS:
        raise InputValidationError("Direction must be either downlink or uplink.", field)


def key_bit(key: bytes, position: int) -> int:
    """Bit ``position`` of the key in loading order: bytes in order, each byte LSB first."""
    return (key[position // 8] >> (position % 8)) & 1


def fn_to_count(fn: int) -> int:
    """Derive the 22-bit COUNT from a TDMA frame number: COUNT = T1 || T3 || T2.

    T1 = FN div (26 x 51), T2 = FN mod 26 and T3 = FN mod 51. FN and COUNT are different
    numbers, so a frame number must not be passed to the cipher without this conversion.
    """
    if not 0 <= fn <= MAX_FN:
        raise InputValidationError(f"The TDMA frame number must be between 0 and {MAX_FN}.", "fn")
    t1, t2, t3 = fn_components(fn)
    return (t1 << 11) | (t3 << 5) | t2


def fn_components(fn: int) -> tuple[int, int, int]:
    """Return (T1, T2, T3) for a TDMA frame number."""
    return fn // (26 * 51), fn % 26, fn % 51


class A51:
    """The three registers and their clocking rules."""

    def __init__(self) -> None:
        self.r1 = 0
        self.r2 = 0
        self.r3 = 0

    @property
    def registers(self) -> tuple[int, int, int]:
        return self.r1, self.r2, self.r3

    def clock_bits(self) -> tuple[int, int, int]:
        return get_bit(self.r1, R1.clock_bit), get_bit(self.r2, R2.clock_bit), get_bit(self.r3, R3.clock_bit)

    def clock_all(self) -> tuple[bool, bool, bool]:
        """Forced clock, used only while the key and COUNT are loaded."""
        self.r1 = clock_register(self.r1, R1)
        self.r2 = clock_register(self.r2, R2)
        self.r3 = clock_register(self.r3, R3)
        return True, True, True

    def clock_majority(self) -> tuple[bool, bool, bool]:
        """Normal clock: only registers whose control bit equals the majority advance."""
        c1, c2, c3 = self.clock_bits()
        maj = majority(c1, c2, c3)
        moved = (c1 == maj, c2 == maj, c3 == maj)
        if moved[0]:
            self.r1 = clock_register(self.r1, R1)
        if moved[1]:
            self.r2 = clock_register(self.r2, R2)
        if moved[2]:
            self.r3 = clock_register(self.r3, R3)
        return moved

    def inject(self, bit: int) -> None:
        """XOR an input bit into bit 0 of all three registers."""
        self.r1 ^= bit
        self.r2 ^= bit
        self.r3 ^= bit

    def output_bits(self) -> tuple[int, int, int]:
        return get_bit(self.r1, R1.output_bit), get_bit(self.r2, R2.output_bit), get_bit(self.r3, R3.output_bit)

    def output(self) -> int:
        o1, o2, o3 = self.output_bits()
        return o1 ^ o2 ^ o3


def generate_frame(key: bytes, count: int, on_step: Callable[[ClockStep], None] | None = None) -> Frame:
    """Run the full key setup and produce both 114-bit sequences for one frame."""
    validate_key(key)
    validate_count(count)
    cipher = A51()

    def forced(phase: str, index: int, bit: int) -> None:
        before = cipher.registers
        controls = cipher.clock_bits()
        moved = cipher.clock_all()
        after_clock = cipher.registers
        cipher.inject(bit)
        if on_step:
            on_step(
                ClockStep(phase, index, bit, before, after_clock, cipher.registers, controls, None, moved,
                          cipher.output_bits(), cipher.output())
            )

    def normal(phase: str, index: int) -> int:
        before = cipher.registers
        controls = cipher.clock_bits()
        moved = cipher.clock_majority()
        # The reference clocks first and then reads the output bits.
        out = cipher.output()
        if on_step:
            on_step(
                ClockStep(phase, index, None, before, cipher.registers, cipher.registers, controls,
                          majority(*controls), moved, cipher.output_bits(), out)
            )
        return out

    for position in range(KEY_BITS):
        forced("key", position, key_bit(key, position))
    for position in range(COUNT_BITS):
        forced("count", position, (count >> position) & 1)
    for cycle in range(WARMUP_CYCLES):
        normal("warmup", cycle)
    downlink = [normal("downlink", i) for i in range(SEQUENCE_BITS)]
    uplink = [normal("uplink", i) for i in range(SEQUENCE_BITS)]
    return Frame(downlink, uplink)


def build_segments(bit_length: int, start_count: int | None = None, start_fn: int | None = None) -> list[Segment]:
    """Split a message of ``bit_length`` bits into frames of up to 114 bits.

    Educational convention: in COUNT mode each new segment uses (COUNT + 1) mod 2^22. In FN
    mode each new segment uses (FN + 1) mod 2715648, and COUNT is derived from that FN.
    """
    if (start_count is None) == (start_fn is None):
        raise ValueError("Provide exactly one of start_count and start_fn.")
    segments: list[Segment] = []
    for index, start_bit in enumerate(range(0, bit_length, SEQUENCE_BITS)):
        length = min(SEQUENCE_BITS, bit_length - start_bit)
        if start_fn is not None:
            fn = (start_fn + index) % FN_MODULUS
            segments.append(Segment(index, start_bit, length, fn_to_count(fn), fn))
        else:
            segments.append(Segment(index, start_bit, length, (start_count + index) % COUNT_MODULUS, None))
    return segments


def crypt_bits(
    key: bytes,
    bits: list[int],
    direction: str,
    start_count: int | None = None,
    start_fn: int | None = None,
) -> CryptResult:
    """Encrypt or decrypt a bit stream, generating a new frame for each segment."""
    validate_key(key)
    validate_direction(direction)
    segments = build_segments(len(bits), start_count, start_fn)
    output: list[int] = []
    keystream: list[int] = []
    for segment in segments:
        sequence = generate_frame(key, segment.count).sequence(direction)
        used = sequence[: segment.length]
        chunk = bits[segment.start_bit : segment.start_bit + segment.length]
        output.extend(a ^ b for a, b in zip(chunk, used))
        keystream.extend(used)
    return CryptResult(output, keystream, segments)
