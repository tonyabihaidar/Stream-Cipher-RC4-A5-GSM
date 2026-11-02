"""RC4 (Rivest Cipher 4), implemented from its published description.

RC4 keeps a secret permutation S of the values 0..255 and two indexes, i and j.

* The Key Scheduling Algorithm (KSA) starts from the identity permutation and uses the
  key to decide which elements to swap.
* The Pseudo-Random Generation Algorithm (PRGA) keeps swapping elements of S while
  emitting one keystream byte per iteration.

``ksa`` and ``prga`` accept an optional ``on_step`` observer. The visualization is built
from those callbacks, so it shows this exact code running and not a second copy of the
algorithm.

RC4 is broken and is implemented here for education only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .encoding_utils import InputValidationError
from .xor_utils import xor_bytes

STATE_SIZE = 256
MIN_KEY_BYTES = 1
MAX_KEY_BYTES = 256


@dataclass(frozen=True)
class KsaStep:
    """One KSA iteration. ``s_i``/``s_j`` are the values before the swap."""

    iteration: int
    i: int
    previous_j: int
    key_index: int
    key_byte: int
    s_i: int
    s_j: int
    j: int
    state: tuple[int, ...]


@dataclass(frozen=True)
class PrgaStep:
    """Generation of one keystream byte. ``s_i``/``s_j`` are the values before the swap."""

    index: int
    previous_i: int
    i: int
    previous_j: int
    j: int
    s_i: int
    s_j: int
    t: int
    keystream_byte: int
    state: tuple[int, ...]


def validate_key(key: bytes, field: str | None = "key") -> None:
    """Standard RC4 accepts keys of 1 to 256 bytes."""
    if not MIN_KEY_BYTES <= len(key) <= MAX_KEY_BYTES:
        raise InputValidationError(
            f"An RC4 key must contain between {MIN_KEY_BYTES} and {MAX_KEY_BYTES} bytes (got {len(key)}).", field
        )


def ksa(key: bytes, on_step: Callable[[KsaStep], None] | None = None) -> list[int]:
    """Key Scheduling Algorithm: return the permutation of 0..255 selected by ``key``."""
    validate_key(key)
    S = list(range(STATE_SIZE))
    j = 0
    for i in range(STATE_SIZE):
        previous_j = j
        key_index = i % len(key)
        s_i = S[i]
        j = (j + s_i + key[key_index]) % STATE_SIZE
        s_j = S[j]
        # Elements are only ever swapped, so S stays a permutation of 0..255.
        S[i], S[j] = S[j], S[i]
        if on_step:
            on_step(KsaStep(i, i, previous_j, key_index, key[key_index], s_i, s_j, j, tuple(S)))
    return S


def prga(
    state: list[int],
    length: int,
    on_step: Callable[[PrgaStep], None] | None = None,
    i: int = 0,
    j: int = 0,
) -> bytes:
    """Generate ``length`` keystream bytes. ``state`` is modified in place as RC4 requires."""
    S = state
    output = bytearray(length)
    for index in range(length):
        previous_i, previous_j = i, j
        i = (i + 1) % STATE_SIZE
        j = (j + S[i]) % STATE_SIZE
        s_i, s_j = S[i], S[j]
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % STATE_SIZE
        output[index] = S[t]
        if on_step:
            on_step(PrgaStep(index, previous_i, i, previous_j, j, s_i, s_j, t, S[t], tuple(S)))
    return bytes(output)


class RC4:
    """A keyed RC4 instance. Keystream continues across calls to ``keystream``."""

    def __init__(self, key: bytes):
        self.S = ksa(key)
        self.i = 0
        self.j = 0

    def keystream(self, length: int) -> bytes:
        S, i, j = self.S, self.i, self.j
        output = bytearray(length)
        for index in range(length):
            i = (i + 1) % STATE_SIZE
            j = (j + S[i]) % STATE_SIZE
            S[i], S[j] = S[j], S[i]
            output[index] = S[(S[i] + S[j]) % STATE_SIZE]
        self.i, self.j = i, j
        return bytes(output)

    def process(self, data: bytes) -> bytes:
        """Encrypt or decrypt: both directions XOR the data with the next keystream bytes."""
        return xor_bytes(data, self.keystream(len(data)))


def rc4_keystream(key: bytes, length: int) -> bytes:
    """First ``length`` keystream bytes for ``key``, from a freshly initialized state."""
    return RC4(key).keystream(length)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """One independent RC4 operation. Encryption and decryption are the same function."""
    return RC4(key).process(data)


def simplified_ksa(
    key: list[int], size: int = 8, on_step: Callable[[KsaStep], None] | None = None
) -> list[int]:
    """Teaching-only KSA over a small array. This is NOT standard RC4."""
    if not key:
        raise InputValidationError("The simplified example needs at least one key value.", "key")
    S = list(range(size))
    j = 0
    for i in range(size):
        previous_j = j
        key_index = i % len(key)
        s_i = S[i]
        j = (j + s_i + key[key_index]) % size
        s_j = S[j]
        S[i], S[j] = S[j], S[i]
        if on_step:
            on_step(KsaStep(i, i, previous_j, key_index, key[key_index], s_i, s_j, j, tuple(S)))
    return S
