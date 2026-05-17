# Byte-faithful PKB-1 demonstration — QR-UOV-Ipks-1 (NIST Category 1)

Operational negative evidence for PKB-1 (same-signature public-key binding) on the upstream QR-UOV Round-2 `portable64` reference (`external/qruov-c/src/portable64`), at parameters **QR-UOV-Ipks-1**: `q=127`, `v=156`, `m=54`, `L=3`.

This is **not** an EUF-CMA forgery: the adversary does not forge a new signature; it constructs an alternative canonical public key under which the **same** honest signature verifies.

## Build and run

From the repository root (requires OpenSSL for the QR-UOV CMake targets):

```bash
mkdir -p build && cd build
cmake ..
cmake --build . --target pkb1_attack_qruov_demo -j"$(nproc)"
./pkb1_attack_qruov_demo              # single trial, full stdout (deterministic trial index 0)
./pkb1_attack_qruov_demo --trials 100 # multi-trial sweep, compact summary
```

Driver: `tests/pkb1_attack_qruov_demo.c`. CMake target: `pkb1_attack_qruov_demo`.

## Deterministic single trial (`--trials` omitted, default 1)

RNG: `randombytes_init` with `rng_seed[i] = (uint8_t)(17*i + 5)` for `i ∈ [0,47]` (trial index 0).

```
=================================================
 Byte-faithful PKB-1 violation: QR-UOV-Ipks-1
 Parameters: q=127, v=156, m=54, L=3
 Trials: 1
=================================================

Honest key generation and signing: OK
  seed_pk      [0d83e88a1ec6ae6f6e6b1844a26374c2]  (16 bytes)
  sig.r (salt) [e43a8015a27c7a8025914efcd88cc5c5]  (16 bytes)
Honest verify: OK

PKB-1 attack construction: OK
  seed_pk*     [b78faaba1be370b8ff3d5ceb928b2240]  (16 bytes)
Attack verify under pk*: OK
pk size (computed): 24256 bytes
pk* != pk (bytewise): OK
bytes that differ: 24160 / 24256 (99.60%)

=================================================
 RESULT: PKB-1 violation operationally confirmed
         on byte-faithful QR-UOV-Ipks-1 reference
         (q=127, v=156, m=54, L=3).
=================================================
```

## Multi-trial sweep (`--trials 100`)

Each trial XOR-mixes the trial index into bytes 0–3 of the 48-byte NIST RNG seed, then runs an independent honest keygen/sign path followed by the same PKB-1 construction.

```
=================================================
 Byte-faithful PKB-1 violation: QR-UOV-Ipks-1
 Parameters: q=127, v=156, m=54, L=3
 Trials: 100
=================================================

SUMMARY: 100 / 100 trials PKB-1 violation confirmed (honest verify, attack verify, pk* != pk)
All trials succeeded.
Example Hamming distance (trial 0 success path): 24160 bytes differ (first successful trial).
```

Machine-readable summary: `pkb1_attack_qruov_byte_faithful.json` in this directory.
