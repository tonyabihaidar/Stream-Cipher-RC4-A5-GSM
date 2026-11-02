# EECE 455 Project 9: Presentation Guide

A 10 to 15 minute live demonstration. Timings add up to about 14 minutes.

## Before you present

```bash
python app.py
```

- Open <http://127.0.0.1:5000> and go full screen. Zoom the browser to 110–125% if the room is large.
- Run `python -m unittest discover -s tests` beforehand, and keep the final `OK` line ready in a terminal.
- **Keyboard:** Left and Right arrows step, Space plays or pauses. These work when focus is not in a text field, so click on an empty part of the page first.
- If something goes wrong during a live step, **Reset** or reloading the page is always safe, since nothing is stored.

## Demonstration plan

### 1. Introduction to stream ciphers (1 min)

**Show:** Compare Algorithms, then expand *What is a stream cipher?*

**Say:** A stream cipher turns a key into a long pseudo-random keystream, and combines it with the message bit by bit. There are no blocks and no padding. We implemented two historically important ones by hand: RC4 and A5/1.

### 2. XOR (1 min)

**Show:** Expand *What is XOR?* and point at the truth table.

**Say:** XOR is its own inverse: (P ⊕ K) ⊕ K = P. So decrypting is the same operation as encrypting. All the difficulty lies in generating the keystream, and that is what the rest of this demo shows.

### 3. RC4 direct encryption (1 min)

**Do:** Direct Encryption/Decryption → RC4 → Example: *Key / Plaintext (published vector)* → **Encrypt**.

**Point out:** The result, `BBF316E8D940AF0AD3`, matches the published vector shown under the example. Note 9 bytes in, 9 keystream bytes, 9 bytes out, and no padding.

### 4. RC4 KSA (2 min)

**Do:** Step-by-Step Visualization → RC4 → build with key `Key` → phase **KSA**. Press Next a few times, then Play at 2x.

**Point out:**
- Teal is `i`, plum is `j`. They swap on screen.
- The equation contains the actual numbers for this step.
- Only the key changes where `j` lands, so the key determines the permutation.

**Then:** Pause, press Previous twice to show the state is restored, and jump to **Shuffled array**: every number is still there exactly once.

### 5. RC4 PRGA (1 min)

**Do:** Phase **PRGA**, then step through two or three bytes.

**Point out:** The array keeps changing. `t` (rust) picks the output byte. The first byte is `EB` for this key, and it appears in the keystream panel.

### 6. RC4 XOR and decryption (1 min)

**Do:** Phase **XOR** and step through the first byte. The bits are `01010000 ⊕ 11101011 = 10111011`, which is `0xBB`, the first ciphertext byte we saw in Direct Mode.

**Then:** Back to Direct Mode → **Send to Decryption** → **Decrypt**. Then change the key and decrypt again to show that a wrong key gives garbage, not an error.

**Say:** Stream ciphers have no integrity check, so nothing tells you the key is wrong.

### 7. A5/1 registers (1 min)

**Do:** Switch to A5/1 → Step-by-Step. The reference key `1223456789ABCDEF` and COUNT `0x134` are already loaded, with message `HI`.

**Point out:** Three registers of 19, 22 and 23 bits, 64 bits in total. Blue outlines are feedback taps, the heavy black outline is the clocking bit, and green is the output bit. Bit 0 is on the right, so new bits enter on the right.

**Then:** Step through a few of **Load key**. All registers clock, then the key bit is XORed into bit 0. The table shows the state before clocking, after clocking and after the XOR.

### 8. Majority clocking (2 min)

**Do:** Phase **Warm-up**, then step slowly, then Play at 1x.

**Point out:**
- The three control bits and their majority.
- Registers matching the majority advance, and the other is dimmed and marked STATIONARY.
- The explanation updates each step, for example: "the majority bit is 1 because two registers have a control bit equal to 1".
- The counter reads `Warm-up cycle N / 100`, and this output is discarded.

**Say:** A regularly clocked LFSR is linear and predictable. Irregular clocking is what A5/1 relies on to break that structure.

### 9. A5/1 keystream generation (1 min)

**Do:** Phase **Keystream**, step a few bits, then drag the progress bar to the end of the phase.

**Point out:** The XOR of the three output bits, computed after the clock. Two blocks of 114 bits: downlink first, then uplink.

**Then:** Mention the check: these blocks equal the published reference, `534EAA58…` and `24FD35A3…`, and the automated tests prove it.

### 10. A5/1 encryption and decryption (1 min)

**Do:** Phase **XOR** and step through a few bits of `HI`. Then in Direct Mode, choose *HI (short message)* → **Encrypt** → **Send to Decryption** → **Decrypt**.

**Point out:** The ciphertext `1B07` matches what the visualization produced. The direction and COUNT are carried across, because decryption must use the same values.

### 11. Short versus long plaintext (1 min)

**Do:** In Direct Mode, point at the numbers for `HI`: 16 bits, 114 generated, 16 used, 98 unused. Then choose *Multi-frame message* → **Encrypt**, and show the frames table with COUNT rising by 1 per segment.

**Say:** We never pad the message. Longer messages reinitialize the cipher with the next COUNT. This is our documented educational convention, not GSM framing, which works on fixed radio bursts.

### 12. Comparison and security limitations (1 min)

**Show:** Compare Algorithms → the table and the security panel.

**Say:** Both ciphers are insecure today. RC4 is biased, and RFC 7465 prohibits it in TLS. A5/1 can be attacked with precomputed tables, and it only protects the radio link, not end to end. Keystream reuse would be fatal for either. This project is about understanding how they work.

**Finish:** Show the terminal with the test results.

## Likely questions

**How do you know the visualization is real?**
Traces are recorded by callbacks inside the same functions that encrypt, and the tests check that traces and Direct Mode give identical output.

**How does going backward work?**
Each step is a complete snapshot from Python. Nothing gets undone, so an earlier step always shows exactly what was true then.

**Why does the A5/1 output get read after clocking?**
That is how the reference implementation behaves. Reading it before clocking would give an apparently working cipher that fails the test vectors.

**What is the difference between FN and COUNT?**
COUNT is the 22-bit value the cipher consumes. It is built from the TDMA frame number as T1 ‖ T3 ‖ T2, so they are different numbers. The app supports both, and it labels which one is in use.

**Why does the Osmocom key look reversed?**
libosmocore stores the same key with its bytes reversed (`key[7 - (i >> 3)]`). We follow the reference code's order, and we test against an Osmocom vector by reversing the key.

**What happens at COUNT 0x3FFFFF?**
The next segment wraps to 0. This is tested.

**Why is the trace limited to 256 bytes?**
Each step is a full snapshot, so traces grow quickly. Direct Mode handles up to 16 KiB.

**Could this be used to intercept GSM calls?**
No. It only processes text you give it. It has no radio, signalling or network component.
