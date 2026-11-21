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
6. [Using the app](#6-using-the-app)
7. [Following the steps](#7-following-the-steps)
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
- Encrypt and decrypt real messages, including Unicode text.
- Show, with a **Show step-by-step** switch on the same page, the real internal states: array permutations, swaps, register contents, majority clocking, keystream generation and XOR.
- Show that the visualization is the real algorithm: traces are recorded from the same functions that do the encryption.

## 2. Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 or later, Flask |
| Ciphers | Python standard library only |
| Frontend | HTML5, CSS3, vanilla JavaScript (ES modules), SVG |
| Tests | Python `unittest` |

The cipher lab uses Flask and vanilla JavaScript. Optional accounts use Firebase Authentication (email/password) and Cloud Firestore. The Firebase SDK is bundled locally; Node.js is needed only to rebuild that bundle or run the Firebase tests. Cipher operations still work without an internet connection once Flask is installed. Sign-in and cloud history require internet access.

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
│       ├── direct_mode.js     Encrypt and Decrypt panels, random keys
│       ├── tour.js            Guided tour behind the Help button
│       ├── visualization_mode.js   Trace setup and step paging
│       ├── step_controls.js   Play, pause, jump, phases, speed, progress
│       ├── rc4_visualization.js    Array grid, equations, XOR view
│       └── a51_visualization.js    SVG registers, clocking, keystream, XOR view
└── tests/                     test_rc4, test_a51, test_encoding, test_api
```

**How the visualization stays honest.** `rc4.ksa`, `rc4.prga` and `a51.generate_frame` take an optional `on_step` callback. Plain encryption calls them without it, and `trace_service.py` passes a callback that records each step. There is no second copy of either algorithm to drift out of sync, and the tests check that traces and direct output agree.

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

## 6. Using the app

Everything happens on one page. The top bar has the **RC4 / A5/1** switch, the **Encrypt & Decrypt** and **Learn Your Algorithms** pages, and a **Help** button.

1. Choose **RC4** or **A5/1** at the top of the page.
2. Enter a message, or pick an **Example**.
3. Enter the key, or press **Random** for a new one. A5/1 also needs COUNT (or a frame number) and a direction.
4. Select **Encrypt**. You get the ciphertext in hex, Base64 and binary, the keystream used, the lengths, and for A5/1 a table of frames.
5. Select **Send to Decryption**, then **Decrypt**. The ciphertext and parameters are copied across, and the original message comes back.

Other features:

- **Help:** a short guided tour. It highlights each part of the page in turn, with **Next** to continue and **Skip** to leave. Esc also closes it.
- **Random keys:** generated in the browser with `crypto.getRandomValues`. RC4 gets 16 bytes, written as hex or as letters and digits depending on the key encoding (`utf-8` or `hex`). A5/1 gets 8 bytes as 16 hex characters.
- **Input formats:** UTF-8 text, hex bytes or binary bits. Binary allows exact bit counts with A5/1, such as exactly 114 bits.
- **Export Record / Import Record:** saves or loads a JSON file containing the ciphertext, algorithm, frame parameters, direction, encoding and bit length. The key is never included.
- **Wrong keys:** a stream cipher cannot detect a wrong key. If the output is not valid UTF-8, the app shows the recovered bytes as hex and explains why.

Encrypt and Decrypt accept up to 16 KiB per message.

## 7. Following the steps

1. Turn on **Show step-by-step**, above the Encrypt and Decrypt panels. The browser remembers this setting.
2. The steps appear below the panels and follow the message and key in the **Encrypt** panel. Loading an example rebuilds them straight away. After editing the message or key, press **Encrypt** to rebuild them.
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

The steps always show encryption. Decryption uses the same keystream and the same XOR, with plaintext and ciphertext swapped.

**RC4 phases:** Initial array → KSA (256 iterations) → Shuffled array → PRGA → XOR. An optional 8-element demonstration sits at the bottom of the page and is labelled as non-standard.

**A5/1 phases:** Clear → Load key (64) → Load COUNT (22) → Initialized → Warm-up (100) → Keystream (228) → XOR.

In the A5/1 diagram, bit 0 is on the right. New bits enter on the right and output bits leave on the left, just as `reg << 1` behaves on a binary number. The diagram shows registers *after* the step's clock, and the state table shows the value before it as well.

Traces are limited to 256 bytes of message, because each step is sent as a full snapshot. Encrypt still works on longer messages: only the steps are skipped.

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

**Encryption and decryption are the same operation:** each byte is XORed with a keystream byte. Keys may be 1 to 256 bytes, entered as `utf-8` text or `hex`. No padding is ever added. Each operation starts from a freshly initialized state.

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

**Privacy:** verified accounts save complete experiments to private Firestore history: key, plaintext, ciphertext, keystream, cipher settings, title, and server timestamp. Anyone who can access the account can read and decrypt its saved experiments. JSON exports include the same sensitive details. Guest encryptions are not saved automatically. Cipher API requests are not logged and responses use `Cache-Control: no-store`. Firestore rules require a verified email and matching account owner; unexpected fields and changes to original experiment data are rejected.

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

## 16. Accounts and saved encryptions

Open `/login` to create an email/password account or sign in. The session survives page reloads in the same tab and ends when that browser session closes or you sign out. New passwords require at least eight characters, uppercase and lowercase letters, a digit, and a Firebase-supported special character. Firebase enforces this policy for new passwords; existing users can still sign in without a forced password change. Password reset is available from the sign-in form. New accounts receive a Firebase email-verification link automatically; existing unverified users can send one from the Account page. Open the link and select **I’ve verified my email** to refresh the session and unlock history. Resends have a one-minute UI cooldown. History access requires email verification both in the app and in Firestore rules. Guests can keep using the entire cipher lab.

While signed in with a verified email, each successful encryption is saved automatically. The result shows whether saving succeeded and offers a retry when it fails. A guest result can also be saved after signing in by returning to the workspace and selecting **Save to History**. Saving reuses one record ID per result so retries do not create duplicates.

**History** shows the newest 25 records and offers **Load older encryptions**. You can rename, export, permanently delete, or open a record in the Decrypt panel. New records include the key, plaintext, input format and keystream in a validated `details` map alongside ciphertext metadata. Expand **View key and full encryption details** to inspect them. Opening a new record restores its key automatically. Older ciphertext-only records remain readable, but their missing keys cannot be recovered and must be entered manually. Signing out clears the forms, visible results, and history. Cipher APIs remain public and stateless; Firestore rules protect all saved data directly.

### Firebase project

This checkout uses `eece-455-stream-cipher`. Its public web configuration is in `static/firebase-config.json`. These browser configuration values are not administrator credentials; access is enforced by Firebase Authentication and `firestore.rules`. Never add service-account keys to this repository.

**Setup status (2026-11-21):** the Firebase project, Web app and Email/Password provider are configured. The default Cloud Firestore Standard database is in Frankfurt (`europe-west3`), on the Spark plan, with the tested `firestore.rules` published. Sign-in and private cloud history are connected.

**Initial ciphertext-only live verification (2026-11-21, before full-detail history):** a disposable account successfully signed in, automatically saved RC4 and A5/1 examples, retained history across reload, renamed a record, and reopened/decrypted both records. The A5/1 record preserved all 114 meaningful bits and its frame parameters. Sign-out cleared keys, results and displayed history. Inspection confirmed that stored records contain only ciphertext and permitted metadata. Both sample records and the temporary account were deleted afterward; the deleted account could no longer sign in. The user's own account and records were untouched. See `artifacts/history-verified.png` for the test history view.

For another deployment:

1. Register a Firebase Web app and place its public config in `static/firebase-config.json`.
2. Enable **Authentication → Sign-in method → Email/Password**. Under **Settings → Password policy**, select **Require enforcement**, minimum length **8**, and require uppercase, lowercase, numeric and special characters. Leave forced upgrade on sign-in off to preserve existing-account access. Firebase’s default verification email template and hosted action handler are used.
3. Create a **Cloud Firestore Standard** database in production mode.
4. Publish the exact rules from `firestore.rules`. The only accessible path is `users/{uid}/encryptions/{id}`, and only the signed-in, email-verified owner can access it. Do not use open test-mode rules.
5. Check Authentication's authorized domains for your intended host (including `localhost` and `127.0.0.1` for local use when required).

The app does not require Firebase Hosting, billing upgrades, Analytics, or service-account credentials. The existing Flask server continues to serve the application and compute cipher operations.

### Rebuild the bundled SDK and verify

The checked-in `static/js/firebase.bundle.js` is generated from `frontend/firebase.js`; do not edit the bundle directly. Rebuild it after changing Firebase versions or exports:

```bash
npm ci
npm run build
npm test
npm run test:rules
npm run test:accounts
```

The Firebase rules tests use a local emulator with a `demo-` project and synthetic accounts, never the live database. Java 21+ is required for the emulator. Tests cover cross-account and signed-out access, ciphertext/metadata validation, validated full encryption details, rejection of unverified users, immutable records, rename/delete permissions, pagination, and retry behavior. Python checks remain `python -m unittest discover -s tests`.

The development dependencies include a project-local Node 24 runtime for the SDK and test tools; npm scripts use it without replacing your system Node installation.

On macOS, if port 5000 is occupied, start locally with:

```bash
.venv/bin/python -m flask --app app run --host 127.0.0.1 --port 5001
```

### Verification and full-detail history checks (2026-11-21)

- 9 JavaScript validation/password checks, 15 Firestore permission/schema checks, and 1 Auth/Firestore integration check pass.
- Five live sign-up attempts with intentionally incomplete password requirements were rejected by Firebase; no live test accounts were created.
- Isolated browser tests verified email resend, the unverified state, one-time verification, refreshed access, RC4/A5/1 automatic saves, persistence after reload, exact key restoration, decryption, and clearing sensitive fields on sign-out. The A5/1 example retained 114 meaningful bits and COUNT 308. See `artifacts/full-history-verified.png`.
- The live Firebase password policy and verified-owner Firestore rules are published. Actual inbox delivery still needs the recipient to check their email; emulator tests do not deliver real mail.
- The Python suite has 147 passing tests and the same two pre-existing Base64-padding failures (`test_invalid_padding` and the `QUJD=` case in `test_ciphertext_validation`).

For an isolated manual browser test, start `npx firebase emulators:start --only auth,firestore --project demo-stream-cipher`, then run `PYTHONPATH=. .venv/bin/python tests/browser_server.py` in another terminal and open `http://127.0.0.1:5002`. This test-only server bundles emulator support and substitutes demo configuration; the normal app has no emulator switch. Emulator verification messages are available through its local out-of-band-code endpoint. Stop both processes after testing.
