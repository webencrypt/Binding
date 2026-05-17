# AnchoredMAYO audit (tier l1-shaped, suite fast-v2)

`N_SEEDS=100`, `n=66`, `m=64`, `q=31`, family-wise α=0.001, Bonferroni threshold=7.14e-05.

## Per-target headline numbers

| Target | P1 rank mean | P2 min-rank median | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|
| `mayo_baseline` | 64.00 | 66.00 | 0 | 0.536 | - |
| `anchored_mayo` | 64.00 | 66.00 | 0 | 0.536 | 0.561 |
| `synthetic_alg_anchor` | 64.00 | 66.00 | 0 | 0.553 | 2.61e-59 |

## P6 PKB-1 violation rates (toy-hash model)

| Mode | n_dpk_bits | n_tau_bits | violations | rate |
|---|---:|---:|---:|---:|
| `anchored_mayo` | 6 | 4 | 0 | 0.0000 |
| `unbound_mq` | 6 | 4 | 4096 | 1.0000 |

## Bonferroni decisions

- `mayo_baseline`: no flag
- `anchored_mayo`: no flag
- `synthetic_alg_anchor`: **SIGNIFICANT (anchor-correlation flag triggered)**