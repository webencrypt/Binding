# Source-code artifact: MQ ownership gap and digest-based PKB profiles

This repository is the source-code artifact accompanying the paper on
the **MQ ownership gap** and its **digest-based public-key-binding
(PKB) repair** for UOV-family signatures. The PDF of the paper is
submitted separately and is **not** included in this artifact.

The artifact contains, for three NIST-track UOV-family references
(MAYO, QR-UOV, SNOVA):

1. **Byte-faithful PKB-1 witnesses.** Standalone C drivers that
   construct, on the *unmodified* upstream reference of QR-UOV-Ipks-1
   and SNOVA-(24,5,16,4), an alternative canonical public key under
   which an *honest* signature verifies. This is operational evidence
   of the PKB-1 gap (same-signature public-key binding); it is **not**
   an EUF-CMA forgery.
2. **Digest-based PKB wrappers.** Three concrete profiles instantiated
   as wrappers around the upstream KeyGen/Sign/Vrfy:
   - `MAYO-PKB` at NIST L1 and L3 (digest-tag);
   - `QR-UOV-PKB-T` (digest-tag) and `QR-UOV-PKB-H`
     (digest-in-target) at QR-UOV-Ipks-1 / NIST L1;
   - `SNOVA-PKB-H` (digest-in-target) at SNOVA-(24,5,16,4) / NIST L1.
3. **Blocking experiments.** For each digest-in-target profile, a
   100-trial deterministic experiment showing that the PKB-H verifier
   rejects every byte-faithful PKB-1 witness produced by the matching
   driver in (1).
4. **Diagnostic audit suite.** The pre-registered probes P1–P8 used
   in the paper as a diagnostic tool for future Class-C anchor
   proposals, plus reproducible JSON / Markdown summaries.

The wrappers and witnesses **do not patch any upstream source**;
they link the upstream reference as-is and add wrapper translation
units only.

---

## Repository layout

```
.
├── CMakeLists.txt              # Single-shot build of every artifact target
├── README.md                   # This file
├── external/
│   ├── mayo-c/                 # Upstream MAYO (vendored)
│   ├── qruov-c/                # Upstream QR-UOV Round-2 (vendored)
│   └── snova-c/                # Upstream SNOVA Round-2 (vendored)
├── mayo_a/                     # MAYO-PKB digest-tag wrapper
│   ├── include/                # mayo_a.h, params_mayo_a_l1.h, params_mayo_a_l3.h, ...
│   └── src/                    # KeyGen / Sign / Open with d_pk + tau
├── qruov_a/portable_glue/      # Glue header / qruov_config.h for the linked-in QR-UOV ref
├── qruov_pkb/                  # QR-UOV-PKB-T (digest-tag) and QR-UOV-PKB-H (digest-in-target)
│   ├── include/
│   └── src/
├── snova_a/                    # SNOVA-PKB-H (digest-in-target)
│   ├── include/snova_pkb.h
│   └── src/                    # snova_pkb_pkdigest.c, snova_pkb_h.c, snova_pkb_compute_hash.c
├── tests/                      # All test_*, bench_*, kat_*, pkb1_attack_* C drivers
├── scripts/audit/              # P1–P8 diagnostic audit suite (Python)
└── reports/                    # Pre-generated KATs, benchmark logs, audit JSON / Markdown
    ├── kat_mayo_a.rsp          # MAYO-PKB-1, 100 records
    ├── kat_mayo_a_l3.rsp       # MAYO-PKB-3, 100 records
    ├── kat_qruov_pkb_t.rsp     # QR-UOV-PKB-T, 100 records
    ├── kat_qruov_pkb_h.rsp     # QR-UOV-PKB-H, 100 records
    ├── kat_snova_pkb_h.rsp     # SNOVA-PKB-H, 100 records
    ├── bench_*.log             # Median-of-200 wall-clock / cycle counts (ref and AVX2)
    └── audit/                  # P1–P8 outputs and the byte-faithful attack logs
```

---

## Requirements

- C99 compiler (GCC 11+ or Clang 14+). AVX2 paths require an x86-64 host.
- CMake ≥ 3.10
- OpenSSL ≥ 1.1 (`libcrypto` only — needed for the linked-in QR-UOV
  reference, which uses SHA-256/SHAKE via the EVP API).
- Python ≥ 3.10 with `numpy`, `galois`, `cryptography` (audit suite only).

On a Debian/Ubuntu host:

```bash
sudo apt install build-essential cmake libssl-dev python3 python3-pip
pip install numpy galois cryptography
```

---

## Build

A single configure step builds all targets that have their
dependencies available; targets with missing dependencies (e.g. no
OpenSSL) are skipped with a CMake status message.

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

This produces ~24 executables under `build/`. The targets are grouped
by profile:

| Profile           | Reference target              | Bench targets                                                  | KAT target       | Selftest target    |
|:------------------|:------------------------------|:---------------------------------------------------------------|:-----------------|:-------------------|
| MAYO-PKB L1       | `external/mayo-c` ref + AVX2  | `bench_mayo_a`, `bench_mayo_a_avx2`, `bench_mayo_baseline`(_avx2) | `kat_mayo_a`     | `test_mayo_a`      |
| MAYO-PKB L3       | `external/mayo-c` ref + AVX2  | `bench_mayo_a_l3`, `bench_mayo_a_l3_avx2`, `bench_mayo_baseline_l3`(_avx2) | `kat_mayo_a_l3` | `test_mayo_a_l3` |
| QR-UOV-PKB-T/H L1 | `external/qruov-c/portable64` | `bench_qruov_pkb`, `bench_qruov_baseline`                       | `kat_qruov_pkb`  | `test_qruov_pkb`   |
| SNOVA-PKB-H L1    | `external/snova-c` ref        | `bench_snova_pkb`, `bench_snova_baseline`                       | `kat_snova_pkb`  | `test_snova_pkb`   |

PKB-1 witness / blocking targets:

| Target                              | What it does                                                                                |
|:------------------------------------|:--------------------------------------------------------------------------------------------|
| `pkb1_attack_qruov_demo`            | Byte-faithful PKB-1 witness on **unmodified** QR-UOV-Ipks-1 (default 1 trial; `--trials N`) |
| `pkb1_attack_snova`                 | Byte-faithful PKB-1 witness on **unmodified** SNOVA-(24,5,16,4) (default 100 trials)        |
| `pkb1_attack_qruov_pkb_block`       | 100-trial blocking experiment: QR-UOV-PKB-H rejects every witness from the line above       |
| `pkb1_attack_snova_pkb_block`       | 100-trial blocking experiment: SNOVA-PKB-H rejects every witness from the line above        |

---

## Reproducing the paper's headline results

All commands below assume the working directory is the build directory:

```bash
cd build
```

### 1. Selftest (every wrapper round-trips, every tamper is rejected)

```bash
./test_mayo_a            # MAYO-PKB-1, 5 sub-tests
./test_mayo_a_l3         # MAYO-PKB-3, 5 sub-tests
./test_qruov_pkb         # QR-UOV-PKB-T and -H, round-trip + 15 negative checks
./test_snova_pkb         # SNOVA-PKB-H, round-trip + 5 negative checks
```

Each driver exits non-zero on the first failure.

### 2. Byte-faithful PKB-1 witnesses on unmodified upstream

```bash
./pkb1_attack_qruov_demo --trials 100   # QR-UOV-Ipks-1, expect 100/100
./pkb1_attack_snova      --trials 100   # SNOVA-(24,5,16,4), expect 100/100
```

Recorded outputs from one run on the artifact host are archived in
`reports/audit/pkb1_attack_qruov_byte_faithful.md` and
`reports/audit/pkb1_attack_snova_byte_faithful.log`. Hamming distances
are `24,160 / 24,256` (QR-UOV) and ~`996 / 1,016` (SNOVA), reproducible
under the deterministic NIST-DRBG seed schedule documented in the
driver sources.

### 3. PKB-H rejects every byte-faithful witness (100 trials)

```bash
./pkb1_attack_qruov_pkb_block          # expect 100/100 PKB-H rejections
./pkb1_attack_snova_pkb_block          # expect 100/100 PKB-H rejections
```

Archived logs:
`reports/audit/pkb1_attack_qruov_pkb_block.log`,
`reports/audit/pkb1_attack_snova_pkb_block.log`.

### 4. Benchmarks (median wall-time / cycles, 200 trials)

```bash
# MAYO-PKB vs upstream MAYO, L1 and L3, ref and AVX2.
./bench_mayo_a              ; ./bench_mayo_baseline
./bench_mayo_a_avx2         ; ./bench_mayo_baseline_avx2
./bench_mayo_a_l3           ; ./bench_mayo_baseline_l3
./bench_mayo_a_l3_avx2      ; ./bench_mayo_baseline_l3_avx2

# QR-UOV-PKB-T/H vs upstream QR-UOV at NIST L1 (qruov1q127L3v156m54).
./bench_qruov_baseline      ; ./bench_qruov_pkb

# SNOVA-PKB-H vs upstream SNOVA-(24,5,16,4).
./bench_snova_baseline      ; ./bench_snova_pkb
```

Logs from the artifact host are in `reports/bench_*.log`. On those
runs, MAYO-PKB overhead is at the noise floor on Sign/Vrfy both at
L1 and L3; QR-UOV-PKB overhead is about `1.4%` on Sign and at most
`7.1%` on Vrfy (the digest-in-target profile keeps the signature
byte-identical to upstream); SNOVA-PKB-H stays within `±1%` of
upstream SNOVA on Sign and Vrfy.

### 5. KAT vectors (100 records per profile)

```bash
./kat_mayo_a                # -> kat_mayo_a.rsp
./kat_mayo_a_l3             # -> kat_mayo_a_l3.rsp
./kat_qruov_pkb             # -> kat_qruov_pkb_t.rsp + kat_qruov_pkb_h.rsp
./kat_snova_pkb             # -> PQCsignKAT_SNOVA_PKB_H.rsp
```

The freshly produced files are byte-identical to the matching files
under `reports/` (see filename mapping in the layout table).

### 6. Diagnostic audit suite (Python)

The audit suite is a diagnostic tool for future Class-C anchor
proposals; it is **not** used as a security proof in the paper.

```bash
python3 scripts/audit/run_audit.py --suite fast --seeds 100 --tier l1-shaped
python3 scripts/audit/run_audit.py --suite deep --seeds 100 --tier l1-shaped \
    --variants synth_a_oilbasis,synth_b_hidden_idx,synth_c_rank1,synth_c_rank2,synth_c_rank4
python3 scripts/audit/run_audit.py --suite snova --seeds 100 --tier l1-shaped
python3 scripts/audit/run_qruov_audit.py --suite qr_uov --seeds 100 --tier qruov-l1-shaped
```

Each run writes a per-target JSON file and a Markdown summary to
`reports/audit/`. The pre-generated outputs in that directory (`audit_*`
and `qruov_audit_*`) are the ones cited by the paper.

---

## Concrete sizes

NIST L1 unless stated; bytes.

| Profile             | pk     | sig | sk  | Notes                                                    |
|:--------------------|-------:|----:|----:|:---------------------------------------------------------|
| MAYO-1 (upstream)   | 1,420  | 454 |  24 | Baseline reference                                       |
| MAYO-PKB-1          | 1,420  | 470 |  64 | digest-tag, pk byte-identical, +16 B tag, +32 B `d_pk` cache |
| MAYO-3 (upstream)   | 2,986  | 681 |  32 | Baseline reference (L3)                                  |
| MAYO-PKB-3          | 2,986  | 705 |  80 | digest-tag, pk byte-identical, +24 B tag, +48 B `d_pk` cache |
| QR-UOV-Ipks-1       | 24,256 | 200 |  32 | Baseline reference                                       |
| QR-UOV-PKB-T        | 24,256 | 216 |  64 | digest-tag, signature = upstream ‖ 16 B tag              |
| QR-UOV-PKB-H        | 24,256 | 200 |  64 | digest-in-target, **byte-identical** signature           |
| SNOVA-(24,5,16,4)   |  1,016 | 248 |  48 | Baseline reference                                       |
| SNOVA-PKB-H         |  1,016 | 248 |  80 | digest-in-target, **byte-identical** signature           |

In every PKB profile the canonical public key is byte-identical to
the upstream wire format; only the secret key and (for digest-tag) the
signature grow, by the cached `d_pk` and (where applicable) the
`tau` tag.

---

## License and provenance

The wrapper sources under `mayo_a/`, `qruov_pkb/`, `snova_a/`,
`tests/`, and `scripts/audit/` are licensed for academic research and
review.

Upstream code under `external/mayo-c/`, `external/qruov-c/` and
`external/snova-c/` is included unmodified and retains the upstream
license and copyright as stated in each subdirectory's `LICENSE` /
`License` file.
