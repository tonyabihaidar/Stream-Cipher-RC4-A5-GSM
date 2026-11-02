# EECE 455 — Stream Cipher Laboratory

**Project 9: RC4 and A5/1 Stream Cipher Implementation and Visualization**

An interactive educational application that implements RC4 and the GSM cipher A5/1 from scratch in Python. You can encrypt and decrypt directly, or step through everything each cipher does internally.

> **Educational use only.** RC4 and A5/1 are broken legacy algorithms. Do not use them to protect real data, and do not enter real SIM keys.

## Contents

1. [Project objectives](#1-project-objectives)
2. [Technology stack](#2-technology-stack)
3. [Project architecture](#3-project-architecture)
4. [Installation and running](#4-installation-and-running)
5. [Running the automated tests](#5-running-the-automated-tests)
6. [Using Direct Mode](#6-using-direct-mode)
7. [Using Visualization Mode](#7-using-visualization-mode)
8. [RC4 explained](#8-rc4-explained)
9. [A5/1 explained](#9-a51-explained)
10. [Plaintext-length handling](#10-plaintext-length-handling)
11. [Bit order and encoding](#11-bit-order-and-encoding)
12. [Test vectors and correctness](#12-test-vectors-and-correctness)
13. [HTTP API](#13-http-api)
14. [Security limitations](#14-security-limitations)
15. [References](#15-references)

## 1. Project objectives

- Implement RC4 and A5/1 by hand, using no cryptography libraries, and verify both against published test vectors.
- Provide a **Direct Mode** for encrypting and decrypting real messages, including Unicode text.
- Provide a **Step-by-Step Mode** showing real internal states: array permutations, swaps, register contents, majority clocking, keystream generation and XOR.
- Show that the visualization is the real algorithm: traces are recorded from the same functions that do the encryption.

## 2. Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 or later, Flask |
| Ciphers | Python standard library only |
| Frontend | HTML5, CSS3, vanilla JavaScript (ES modules), SVG |
| Tests | Python `unittest` |

There is no Node.js, npm, frontend framework, database or Docker. The frontend loads nothing from the internet, so the app runs offline once Flask is installed.

## 3. Project architecture

```text
EECE455_Project/
├── app.py                     Flask routes, error handling, security headers
├── requirements.txt
├── README.md
├── PRESENTATION_GUIDE.md
├── algorithms/                The ciphers. No Flask imports.
│   ├── rc4.py                 KSA, PRGA, RC4 class, 8-element teaching KSA
│   ├── a51.py                 Registers, clocking, key setup, frames, segments
│   ├── xor_utils.py           XOR for bytes and bit lists
│   └── encoding_utils.py      UTF-8, hex, Base64, bit packing, validation errors
├── services/
│   ├── cipher_service.py      Input validation, encrypt and decrypt, records
│   ├── trace_service.py       Step traces recorded from the algorithms
│   └── examples.py            One-click examples
├── templates/index.html       The single page
├── static/
│   ├── css/                   style.css, animations.css
│   └── js/
│       ├── app.js             Selected algorithm and view
│       ├── api.js             JSON API client
│       ├── dom.js             Shared DOM and form helpers
│       ├── direct_mode.js     Direct Mode
│       ├── visualization_mode.js   Trace setup and step paging
│       ├── step_controls.js   Play, pause, jump, phases, speed, progress
│       ├── rc4_visualization.js    Array grid, equations, XOR view
│       └── a51_visualization.js    SVG registers, clocking, keystream, XOR view
└── tests/                     test_rc4, test_a51, test_encoding, test_api
```

**How the visualization stays honest.** `rc4.ksa`, `rc4.prga` and `a51.generate_frame` take an optional `on_step` callback. Direct Mode calls them without it, and `trace_service.py` passes a callback that records each step. There is no second copy of either algorithm to drift out of sync, and the tests check that traces and direct output agree.

**How going backward works.** Every step is a complete snapshot of the state, so moving back just displays an earlier snapshot. No swap or register shift is ever undone.

**How large traces stay light.** `/api/visualize` is stateless. It recomputes from the inputs and returns one page of steps at a time. The browser caches pages and fetches the next one early during playback. The server keeps no keys or trace data between requests.

## 4. Installation and running

You need Python 3.11 or later.

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks the activation script, use `.venv\Scripts\Activate.ps1` after running `Set-ExecutionPolicy -Scope Process RemoteSigned`, or run the commands from Command Prompt.

### macOS and Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

### Open the app

Go to <http://127.0.0.1:5000>. Stop the server with `Ctrl+C`.

## 5. Running the automated tests

```bash
python -m unittest discover -s tests -v
```

| File | What it covers |
|---|---|
| `test_rc4.py` | KSA, permutation invariants, PRGA, RFC 6229 vectors, symmetry, key limits, trace accuracy |
| `test_a51.py` | Register layout, feedback, majority clocking, key setup order, reference vectors, FN conversion, message lengths, multi-frame processing, trace accuracy |
| `test_encoding.py` | UTF-8, hex, Base64, bit packing and padding, integer parsing, XOR |
| `test_api.py` | Both ciphers through Flask, error handling, limits, records without keys, Direct and Visualization agreement, frontend contract checks |

The tests do not run the JavaScript in a browser. `test_api.py` statically checks that the scripts and the backend agree on field names and element IDs.

## 6. Using Direct Mode

1. Choose **RC4** or **A5/1** at the top of the page.
2. Enter a message, or pick an **Example**.
3. Enter the key. A5/1 also needs COUNT (or a frame number) and a direction.
4. Select **Encrypt**. You get the ciphertext in hex, Base64 and binary, the keystream used, the lengths, and for A5/1 a table of frames.
5. Select **Send to Decryption**, then **Decrypt**. The ciphertext and parameters are copied across, and the original message comes back.

Other features:

- **Input formats:** UTF-8 text, hex bytes or binary bits. Binary allows exact bit counts with A5/1, such as exactly 114 bits.
- **Export Record / Import Record:** saves or loads a JSON file containing the ciphertext, algorithm, frame parameters, direction, encoding and bit length. The key is never included.
- **Wrong keys:** a stream cipher cannot detect a wrong key. If the output is not valid UTF-8, the app shows the recovered bytes as hex and explains why.

Direct Mode accepts up to 16 KiB per message.

## 7. Using Visualization Mode

1. Open **Step-by-Step Visualization**. A default trace is built automatically.
2. Change the message or key and select **Build Visualization**, or pick an example.
3. Navigate with these controls:

| Control | Action |
|---|---|
| Phase buttons | Jump to a stage of the algorithm |
| Start | Rewind to step 1 and play |
| Previous / Next | Move one step (keyboard: Left / Right arrows) |
| Play / Pause | Toggle playback (keyboard: Space) |
| Reset | Stop and return to step 1 |
| Speed | 0.5x, 1x, 2x or 4x |
| Jump to step | Go to a step number |
| Progress bar | Drag to any step |
| XOR by (A5/1) | Step through the XOR phase by bit or by byte |
| Frame traced (A5/1) | For multi-frame messages, choose which frame's registers to show |

**RC4 phases:** Initial array → KSA (256 iterations) → Shuffled array → PRGA → XOR. An optional 8-element demonstration sits at the bottom of the page and is labelled as non-standard.

**A5/1 phases:** Clear → Load key (64) → Load COUNT (22) → Initialized → Warm-up (100) → Keystream (228) → XOR.

In the A5/1 diagram, bit 0 is on the right. New bits enter on the right and output bits leave on the left, just as `reg << 1` behaves on a binary number. The diagram shows registers *after* the step's clock, and the state table shows the value before it as well.

Traces are limited to 256 bytes of message, because each step is sent as a full snapshot. Use Direct Mode for longer messages.

## 8. RC4 explained

RC4 keeps a permutation `S` of the values 0 to 255.

**KSA** shuffles `S` using the key:

```python
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]
```

**PRGA** keeps swapping, and emits one byte per iteration:

```python
i = (i + 1) % 256
j = (j + S[i]) % 256
S[i], S[j] = S[j], S[i]
keystream_byte = S[(S[i] + S[j]) % 256]
```

**Encryption and decryption are the same operation:** each byte is XORed with a keystream byte. Keys may be 1 to 256 bytes, entered as UTF-8 text or hex. No padding is ever added. Each operation starts from a freshly initialized state.

## 9. A5/1 explained

Three LFSRs hold 64 bits of state. Bit 0 is the least significant bit.

| Register | Length | Feedback taps | Clocking bit | Output bit |
|---|---|---|---|---|
| R1 | 19 | 13, 16, 17, 18 | 8 | 18 |
| R2 | 22 | 20, 21 | 10 | 21 |
| R3 | 23 | 7, 20, 21, 22 | 10 | 22 |

Clocking a register computes the XOR of its taps, shifts left by one within its mask, and inserts the result at bit 0.

**Frame generation, in the reference order:**

1. Clear all registers.
2. For each of the 64 key bits: clock all registers, then XOR the bit into bit 0 of each. Key bytes are used in order, and each byte is read least significant bit first.
3. For each of the 22 COUNT bits, least significant first: the same procedure.
4. Run 100 majority-clocked cycles and discard the output.
5. Run 228 majority-clocked cycles. **After** each clock, output `R1[18] ^ R2[21] ^ R3[22]`. The first 114 bits are downlink, the next 114 are uplink.

**Majority clocking:** take the three clocking bits and find their majority. Only registers whose clocking bit equals the majority advance, so at least two registers move on each cycle.

**COUNT and the TDMA frame number are different.** The primary input is the 22-bit COUNT that the cipher consumes. You can instead enter a GSM TDMA frame number (FN, 0 to 2715647), which is converted as in libosmocore:

```text
T1 = FN div (26 x 51)      T2 = FN mod 26      T3 = FN mod 51
COUNT = (T1 << 11) | (T3 << 5) | T2
```

**Key byte order differs between references.** This project follows the Briceno-Goldberg-Wagner reference code and the classic test vector, so bytes load in written order. libosmocore reads `key[7 - (i >> 3)]`, which means it stores the same key with its bytes reversed:

| Convention | Same key |
|---|---|
| This project and the reference code | `12 23 45 67 89 AB CD EF` |
| libosmocore | `EF CD AB 89 67 45 23 12` |

Bits within each byte are read least significant first in both. To use an Osmocom key in this app, reverse its bytes. The test suite confirms this with an Osmocom vector.

## 10. Plaintext-length handling

A5/1 produces 114 bits per direction per frame, but the app does not require 114 bits of input. A message is treated as a bit stream and is never padded.

| Message | What happens | Example |
|---|---|---|
| **Under 114 bits** | One frame. The first N keystream bits are used, and the rest are discarded. | `HI` = 16 bits: 114 generated, 16 used, 98 unused, 16-bit ciphertext |
| **Exactly 114 bits** | One frame, fully used. | Binary input of 114 bits |
| **Over 114 bits** | Split into segments of up to 114 bits, with a new frame for each. | 200 bits: 114 bits, then 86 bits from a new 114-bit block |

### Educational multi-frame convention

This is **not** GSM framing. Real GSM encrypts fixed radio bursts and does not define a way of splitting arbitrary messages. The convention used here is:

- **COUNT mode:** segment *k* uses `(COUNT + k) mod 2^22`. After `0x3FFFFF` comes `0x000000`.
- **FN mode:** segment *k* uses `(FN + k) mod 2715648`, and each segment's COUNT is derived from its own FN. Consecutive FNs do not give consecutive COUNTs.
- The cipher is fully reinitialized with the same key for each segment.
- Only the selected direction's keystream is used, so for each segment 114 bits count as generated.

RC4 needs none of this, because it generates exactly as many bytes as the message has.

## 11. Bit order and encoding

The same rules apply to every operation:

- **Text → bytes:** UTF-8. Characters are never XORed directly, so `مرحبا` is 10 bytes.
- **Byte → bits:** most significant bit first. `H` (0x48) is `01001000`.
- **Keystream consumption:** in generation order, with the first bit XORed against the first message bit.
- **Bits → serialized form:** most significant bit first. Zero bits fill the last byte if necessary, which is the same packing as the published vectors (114 bits + 6 zero bits = 15 bytes).
- **Padding belongs to the representation only.** The meaningful bit length is reported and saved in the exported record, and decryption removes the padding. If a stated bit length would leave non-zero padding bits, the request is rejected because the data must be corrupted.

## 12. Test vectors and correctness

All of the following are checked by the test suite.

| Algorithm | Input | Expected | Source |
|---|---|---|---|
| RC4 | Key `Key`, plaintext `Plaintext` | `BBF316E8D940AF0AD3` | Common published vector |
| RC4 | Key `0102030405` | First 16 bytes `B2396305F03DC027CCC3524A0A1118A8` | RFC 6229 |
| RC4 | 40, 56, 64 and 128-bit keys | Keystream at offsets 0, 16, 240 and 4080 | RFC 6229 |
| A5/1 | Key `1223456789ABCDEF`, COUNT `0x134` | Downlink `534EAA582FE8151AB6E1855A728C00` | Briceno, Goldberg, Wagner |
| A5/1 | Same | Uplink `24FD35A35D5FB6526D32F906DF1AC0` | Briceno, Goldberg, Wagner |
| A5/1 | Osmocom key `0123456789ABCDEF`, FN 123456 | Downlink `CBA25576175D3B1C7B2F29A8C1B600`, uplink `D9035E0F2AEC139A05D4A87BB16480` | libosmocore `tests/a5/a5_test.c` |

The A5/1 hex values hold 114 bits in 15 bytes, with 6 zero padding bits at the end. The Osmocom vector independently confirms the FN conversion, the key byte order and the direction mapping.

The output of the `Hello World`, `HI`, `Hello GSM` and multi-frame examples has no published reference. Those are calculated by the implementation when the example list is requested.

## 13. HTTP API

All POST endpoints take and return JSON. Errors look like `{"error": {"code", "message", "field"}}`.

| Route | Purpose |
|---|---|
| `GET /` | The application |
| `POST /api/encrypt` | Encrypt: `algorithm`, `key`, `plaintext`, `input_format`, plus the parameters below |
| `POST /api/decrypt` | Decrypt: `algorithm`, `key`, `ciphertext`, `ciphertext_encoding`, optional `bit_length`, plus the parameters below |
| `POST /api/visualize` | One page of a trace: the encrypt fields, plus `start` or `phase`, `count_steps`, `segment`, `include_summary` |
| `POST /api/simplified-rc4` | The 8-element teaching example: `key` as a list of numbers |
| `GET /api/examples` | The one-click examples |
| `GET /api/limits` | Size limits |
| `GET /api/health` | Health check |

- **RC4 parameters:** `key_encoding` (`text` or `hex`).
- **A5/1 parameters:** `direction` (`downlink` or `uplink`), `count_mode` (`count` or `fn`), and `count` or `fn` (decimal or `0x` hex).

Status codes are 400 for invalid input, 404, 405, 413 for oversized requests and 415 for a non-JSON content type. Unexpected errors return a generic 500 message with no internal details.

**Privacy:** nothing is stored. Keys and messages are not logged, API responses are sent with `Cache-Control: no-store`, and the key is not repeated in any response.

## 14. Security limitations

- **Do not use either cipher to protect real data.** RC4 output is biased, and RFC 7465 prohibits it in TLS. A5/1 can be attacked with precomputed tables.
- **A5/1 is not end-to-end encryption.** It protects only the radio link between a handset and a base station.
- **Keystream reuse is fatal.** If two messages use the same key and frame value, then `C1 ^ C2 = P1 ^ P2`. Neither this app nor the ciphers prevent you from reusing them.
- **No integrity.** Flipping a ciphertext bit flips the same plaintext bit, and nothing detects it.
- **Not a GSM implementation.** There is no authentication, key agreement, signalling or radio framing, and no connection to mobile networks.
- **Not hardened software.** It uses the Flask development server, binds to `127.0.0.1`, and is meant for local demonstrations only. Do not expose it to a network.

## 15. References

- Rivest Cipher 4 test vectors: [RFC 6229](https://www.rfc-editor.org/rfc/rfc6229)
- Prohibiting RC4 in TLS: [RFC 7465](https://www.rfc-editor.org/rfc/rfc7465)
- M. Briceno, I. Goldberg and D. Wagner, *A pedagogical implementation of the GSM A5/1 and A5/2 "voice privacy" encryption algorithms*
- Osmocom libosmocore: [A5 documentation](https://downloads.osmocom.org/api/latest/libosmocore/gsm/html/group__a5.html), `src/gsm/a5.c` and `tests/a5/a5_test.c`
