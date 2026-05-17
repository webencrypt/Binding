# AnchoredMAYO audit (tier snova-l1-shaped, suite fast-v3)

`N_SEEDS=100`, `n=66`, `m=24`, `q=31`, family-wise α=0.001, Bonferroni threshold=5.88e-05.

## Per-target headline numbers

| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|---:|
| `snova_baseline` | 24.00 | 66.00 | - | 0 | 0 | - |
| `snova_anchored` | 24.00 | 66.00 | 1 | 0 | 0 | 0.846 |
| `snova_synthetic` | 24.00 | 66.00 | 5.59e-20 | 0 | 0 | 2.61e-59 |

## P6 PKB-1 violation rates (toy-hash model)

| Mode | n_dpk_bits | n_tau_bits | violations | rate |
|---|---:|---:|---:|---:|
| `anchored_mayo` | 6 | 4 | 0 | 0.0000 |
| `unbound_mq` | 6 | 4 | 4096 | 1.0000 |

## Bonferroni decisions

- `snova_baseline`: no flag
- `snova_anchored`: no flag
- `snova_synthetic`: **SIGNIFICANT (P5 anchor-corr, P3 wedge)**