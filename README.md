# Tibeb CTF 2026 — Full-Sweep Write-Up

**Team Adwa** · Captain: **Abol Mohamed (AK40)**

![Score](https://img.shields.io/badge/Score-7%2C300%20pts-brightgreen)
![Solved](https://img.shields.io/badge/Solved-27%2F27-success)
![First Bloods](https://img.shields.io/badge/First%20Bloods-19%2B-orange)
![Categories](https://img.shields.io/badge/Categories-6-blue)

A complete solution write-up for **Tibeb CTF 2026**, covering all 27 challenges across six categories: Web, Crypto, Pwn, Reversing, Forensics, and Misc. This document captures the technique, methodology, and defensive takeaway for every challenge solved.

> **Evidence note:** Flags and statistics below are reproduced exactly as recorded during the competition. Independent re-verification would require the original challenge binaries/artifacts and official scoreboard records, which are not redistributed here for integrity reasons.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Toolchain & Methodology](#2-toolchain--methodology)
3. [Web (2 challenges)](#3-web)
4. [Crypto (6 challenges)](#4-crypto)
5. [Pwn (5 challenges)](#5-pwn)
6. [Reversing (4 challenges)](#6-reversing)
7. [Forensics (5 challenges)](#7-forensics)
8. [Misc (5 challenges)](#8-misc)
9. [Key Takeaways & Remediation Checklist](#9-key-takeaways--remediation-checklist)

---

## 1. Executive Summary

Team Adwa solved all 27 challenges in Tibeb CTF 2026, scoring **7,300 points** with **19+ first bloods** across six categories:

| Category | Challenges | Count |
|---|---|---|
| Web | #01, #02 | 2 |
| Crypto | #03–#07, #17 | 6 |
| Pwn | #08–#12 | 5 |
| Reversing | #13–#16 | 4 |
| Forensics | #18–#22 | 5 |
| Misc | #23–#27 | 5 |

**Recurring pattern:** nearly every challenge reduced to one of two root causes — an **implementation failure** (a protocol, parser, or crypto primitive used incorrectly) or a **hidden data path** (information left recoverable in a file, protocol, or data structure that was assumed to be opaque). Recognizing which of these two patterns applies is usually the fastest route to the first foothold.

---

## 2. Toolchain & Methodology

| Category | Primary Tools |
|---|---|
| **Web** | Browser DevTools, `curl`, JWT inspection, controlled template-injection probes |
| **Crypto** | Python, modular arithmetic, `gcd`, modular inverse, finite-field (GF(257)) arithmetic |
| **Pwn** | `checksec`, `gdb` (+ GEF/pwndbg), `pwntools`, `nm`, `objdump`, ASan/UBSan |
| **Reversing** | Ghidra, radare2, `strings`, `wasm2wat`, custom VM emulation |
| **Forensics** | `file`, `xxd`, `binwalk`, `tshark`, SQLite page-level inspection, Pillow |

### 7-Step General Methodology

A consistent process was applied to every challenge, regardless of category:

1. **Preserve originals** — hash and work only on copies; never modify source artifacts.
2. **Enumerate** — identify format, routes, protections, protocol fields, and metadata before any exploitation attempt.
3. **Probe minimally** — test with low-impact inputs first; distinguish reflection from evaluation.
4. **Automate transforms** — script repeatable byte-level operations; record encoding, byte order, offsets, and moduli explicitly.
5. **Validate** — confirm results against the expected success condition and flag format.
6. **Document** — log exact commands and outputs; separate observed fact from inference.
7. **Translate to defense** — convert each exploit into a concrete defensive control or regression test.

---

## 3. Web

### #01 — pass-office
**Technique:** JWT `alg:none` acceptance

**Approach:** Decoded the JWT header/payload, inspected the server's algorithm allow-list, and (in the authorized sandbox) crafted an unsigned token carrying a staff role. Sent it as a `Bearer` token to `/desk`.

```
header.payload.        ← empty signature segment
```

**Flag:** `tibeb{pass_office_cbdeb320770518703679}`

### #02 — The Template Loom
**Technique:** Jinja2 Server-Side Template Injection (SSTI) → command execution

**Approach:** Confirmed template evaluation with a benign probe, identified the Jinja2 engine, and (within the authorized sandbox) used Python object traversal to reach `os.popen`.

```
{{ cycler.__init__.__globals__.os.popen('cat /run/secrets/flag').read() }}
```

**Flag:** `tibeb{loom_ce82addc3d9a84b6a9dd}`

**Remediation:** Enforce a JWT algorithm allow-list and server-side authorization checks; never evaluate user input as template source, and sandbox template rendering with least privilege.

---

## 4. Crypto

| # | Name | Technique | Approach | Flag |
|---|---|---|---|---|
| 03 | Shift Change | Caesar ROT-15 | Decrypted with shift −15 mod 26, preserving punctuation | `tibeb{caesar_cc51e682fccb68834c53}` |
| 04 | One Pad, Two Letters | One-Time-Pad reuse | XOR'd two ciphertexts to cancel the shared pad, recovered plaintext via crib-dragging | `tibeb{reused_pad_4c7dc6f971caa3faa822}` |
| 05 | Correction Window | AES-CTR malleability | Used a known-plaintext ciphertext to recover the keystream, then XOR'd it against the target | `tibeb{ctr_edit_956af5519f2e87de808d}` |
| 06 | Shared Workshop | RSA shared-prime factorization | Computed `gcd(n1, n2)` to recover a shared factor, derived φ(n) and the private exponent | `tibeb{shared_prime_ca82e244fdb177739eb1}` |
| 07 | Nonce Echo | DSA nonce reuse | Found two signatures sharing nonce `r`, solved for `k` and the private key | `tibeb{nonce_echo_bc41f9801131ec8894dd}` |
| 17 | Sixteen Brass Dials | Gaussian elimination over GF(257) | Built and row-reduced a linear system modulo the prime 257 | `tibeb{equations_bd5e5c8d2f4e00aae04c}` |

**Core math used:**

```
Caesar:   D(c) = (c − 15) mod 26
OTP:      P2 = (C1 ⊕ C2) ⊕ P1
AES-CTR:  P = C_orig ⊕ C_zero
RSA:      p = gcd(n1, n2);  d = e⁻¹ mod φ(n)
DSA:      k = (h1 − h2)(s1 − s2)⁻¹;  x = (s1·k − h1)·r⁻¹ mod q
```

**Remediation:** Use AEAD ciphers (AES-GCM, ChaCha20-Poly1305); never reuse cryptographic nonces or one-time pads; generate RSA primes independently with a CSPRNG; use vetted signing libraries rather than hand-rolled DSA.

---

## 5. Pwn

| # | Name | Technique | Approach | Flag |
|---|---|---|---|---|
| 08 | Narrow Counter | 16-bit integer truncation | Traced a checked value through a narrowing conversion to a later unguarded use | `tibeb{narrow_counter_6334556160b538ab31b6}` |
| 09 | Printf Post | Format-string disclosure | Sent bounded `%p` probes against an unguarded `printf(user_input)` call | `tibeb{printf_post_aea77073f7b5280608d7}` |
| 10 | Night Return | Stack overflow / ret2win | Built a 72-byte padding + alignment gadget + win-function address payload | `tibeb{night_return_6ce4aa378821718178d4}` |
| 11 | Borrowed Badge | Use-after-free / heap reuse | Traced the allocation→free→stale-pointer path and reused the freed chunk | `tibeb{borrowed_badge_58d87fd6a05220b3d6d2}` |
| 12 | Two Seals | ROP register setup | Chained `pop rdi`/`pop rsi` gadgets to set up arguments for a protected routine | `tibeb{two_seals_90f0d4e024cac917d9d4}` |

**Representative payload shapes:**

```python
# #10 — ret2win
payload = b'A' * 72 + p64(ALIGN_RET) + p64(WIN_ADDR)

# #12 — ROP chain
payload = padding + pop_rdi + arg1 + pop_rsi + arg2 + align + p64(vault_addr)
```

**Remediation:** Bound-check before every narrowing conversion; never pass user input directly as a `printf` format string; build with stack canaries, PIE, full RELRO, NX, and FORTIFY_SOURCE; fuzz with ASan/UBSan in CI.

---

## 6. Reversing

| # | Name | Technique | Approach | Flag |
|---|---|---|---|---|
| 13 | XOR Gate | Single-byte XOR | Inverted the comparison byte with `0x6D` | `tibeb{xor_gate_e8e207113ff8a92a0f27}` |
| 14 | Tiny Rotor | Add/rotate/XOR chain | Reversed the transform: XOR `0xA7` → rotate right 3 → subtract `7i mod 256` | `tibeb{rotor_1b21babb4d1cc247a9f2}` |
| 15 | Pocket WebAssembly | WASM data-segment XOR | Converted with `wasm2wat`, located the data segment, reversed `0x5A` XOR | `tibeb{wasm_lock_626955ef5b1eef4750eb}` |
| 16 | Museum Machine | Custom VM bytecode inversion | Mapped opcodes/operand sizes/state transitions, inverted the acceptance predicate | `tibeb{bytecode_dc67f143d19b57109e1e}` |

**Key insight:** obfuscation (XOR layers, bit rotation, custom bytecode VMs) is reversible by construction — it adds analysis friction, not confidentiality. None of these techniques protect a secret the way a proper cryptographic primitive would.

**Remediation:** Never treat obfuscation as secret storage; keep real secrets server-side or in a managed secret store; use obfuscation only as one layer of defense-in-depth, never the sole control.

---

## 7. Forensics

| # | Name | Technique | Approach | Flag |
|---|---|---|---|---|
| 18 | After the Last Pixel | ZIP appended after PNG `IEND` | Located the trailer past `IEND`, carved and extracted the embedded archive | `tibeb{png_tail_65445df5f21363883f58}` |
| 19 | Postcards in DNS | Base32 DNS exfiltration | Extracted DNS query names from a PCAP, sorted/concatenated encoded labels, Base32-decoded | `tibeb{dns_postcards_40c25cd99724e8be47f7}` |
| 20 | The Logbook | Out-of-order log fragments | Filtered by marker, sorted by sequence number, concatenated and Base64-decoded | `tibeb{logbook_81c647feecdc885b06fe}` |
| 21 | Pixel Weave | Red-channel LSB steganography | Extracted the LSB of each red channel value, read a 4-byte big-endian length prefix | `tibeb{pixel_weave_0703d066f23ffb3e6141}` |
| 22 | Erased Ledger | SQLite freelist carving | Carved freelist pages from a copied database, located a marker string, Base64-decoded | `tibeb{erased_ledger_d38cd8fca9884a3df28d}` |

**Commands used:**

```bash
# #18 — carve appended ZIP from PNG
dd if=poster.png bs=1 skip=180 of=hidden.zip

# #19 — extract DNS query names from a capture
tshark -r postcards.pcap -Y 'dns' -T fields -e dns.qry.name

# #22 — carve SQLite freelist pages
dd if=ledger.sqlite bs=4096 skip=3 count=3 of=free_pages.bin
```

**Remediation:** Validate uploaded files/archives at every trust boundary; monitor DNS egress for anomalous label patterns; keep structured, immutable logs with sequence IDs; retain evidence copies with hashes.

---

## 8. Misc

| # | Name | Technique | Approach | Flag |
|---|---|---|---|---|
| 23 | Matryoshka Parcel | Nested gzip/Base64/BZIP2/ZIP | Identified and peeled each encoding layer by magic bytes, saving intermediates | `tibeb{matryoshka_a52321d3fbea56b2bea3}` |
| 24 | Campus Footprints | Latest-revision data correlation | Selected the latest record per event, concatenated seals in stated order | `tibeb{campus_footprints_70526293eea545fbeb69}` |
| 25 | Midnight Signal | Morse timing → Base32 | Classified dot/dash by duration, split on silence gaps, translated, then Base32-decoded | `tibeb{signal_028ddd57ccb53cbace6d}` |
| 26 | Caravan Routes | Dijkstra shortest path | Parsed a weighted graph, ran Dijkstra, reconstructed the path, concatenated edge labels | `tibeb{caravan_4489ddfd760148f6bd3f}` |
| 27 | Repair Shop | Hamming(7,4) error correction | Split into 7-bit codewords, computed syndromes, corrected bit errors, extracted data bits | `tibeb{repair_shop_4d3641cf53f7f3caefe7}` |

**Remediation:** Extract untrusted archives in isolated directories; validate record schemas and ordering; document bit-order conventions explicitly; use end-to-end checksums and appropriate error-correcting codes.

---

## 9. Key Takeaways & Remediation Checklist

### Lessons Learned

1. Pin JWT algorithms; enforce authorization server-side, never trust client-supplied claims.
2. Keep user input out of template source and format strings entirely.
3. Use AEAD ciphers; never reuse cryptographic nonces or one-time pads.
4. Bound-check before every narrowing conversion; harden native builds with modern mitigations.
5. Obfuscation is not confidentiality — keep real secrets server-side.
6. Assume files, DNS traffic, logs, images, and databases all retain recoverable evidence.
7. Preserve hashes, exact commands, raw outputs, and stated assumptions for every step.

### Remediation Checklist

- [ ] JWT algorithm allow-list, strict claim validation, replay protection
- [ ] Template sandboxing, output escaping, least-privilege rendering
- [ ] AEAD encryption, unique nonces, vetted cryptographic libraries
- [ ] Bounds checks, safe `printf` usage, ASan/UBSan in CI, PIE/RELRO/NX enabled
- [ ] File/archive validation on upload, DNS egress monitoring, immutable audit logs
- [ ] Schema validation, checksums, and parity/bit-order documentation for data formats

---

## Closing

**Team Adwa** · Captain: **Abol Mohamed (AK40)**
**Result:** 7,300 points · 27/27 challenges solved · 19+ first bloods

*Flags and statistics in this write-up are reproduced from competition records. This document is shared for educational and portfolio purposes — it demonstrates methodology across Web, Cryptography, Binary Exploitation, Reverse Engineering, Digital Forensics, and Miscellaneous CTF categories.*
