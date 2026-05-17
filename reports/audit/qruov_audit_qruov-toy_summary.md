# QR-UOV-shape audit (tier qruov-toy, suite qruov-fast-v1)

`N_SEEDS=200`, `n=12`, `m=8`, `q=31`, `d_g=2`, family-wise α=0.001, Bonferroni threshold=6.67e-05.

Anchor = monic ``g(y)`` coefficients, ascending (constant term first; leading 1 included as last byte).  ``g(y)`` is **algebraically consumed** by every multiplication in ``L``, putting plain QR-UOV into the high-risk anchor class of our taxonomy (Class C).

## Per-target headline numbers

| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|
| `qruov_baseline` | 8.00 | 12.00 | 0.208 | 0.468 | 0.8 |
| `qruov_synth_sparse_g` | 8.00 | 12.00 | 1 | 0.553 | 0.309 |
| `qruov_synth_pinned_g` | 8.00 | 12.00 | 2.89e-42 | 0.736 | 2.09e-123 |

## Bonferroni decisions

- `qruov_baseline`: no flag
- `qruov_synth_sparse_g`: no flag
- `qruov_synth_pinned_g`: **SIGNIFICANT (P5 anchor-corr, P3 wedge)**

## Interpretation

- `qruov_baseline` is the canonical QR-UOV shape with a fresh irreducible ``g(y)`` per seed.  A flag here would indicate that the modulus *as it varies across the deployment family* leaks structurally into the public map -- a finding worth reporting on the QR-UOV family.
- `qruov_synth_sparse_g` simulates a *weak modulus* regime (two-term ``g(y)``).  Flagging this confirms the audit framework's structural sensitivity matches the Lin--Wang 2024 detection signal on sparse-modulus QR-UOV; failing to flag is a calibration result.
- `qruov_synth_pinned_g` is a unit test: the framework MUST flag it.