# AnchoredMAYO audit (tier toy, suite fast-v2)

`N_SEEDS=30`, `n=12`, `m=4`, `q=31`, family-wise α=0.001, Bonferroni threshold=7.14e-05.

## Per-target headline numbers

| Target | P1 rank mean | P2 min-rank median | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|
| `mayo_baseline` | 4.00 | 12.00 | 0 | 0.9 | - |
| `anchored_mayo` | 4.00 | 12.00 | 0 | 0.9 | 0.0414 |
| `synthetic_alg_anchor` | 4.00 | 12.00 | 0 | 0.871 | 1.63e-15 |

## P6 PKB-1 violation rates (toy-hash model)

| Mode | n_dpk_bits | n_tau_bits | violations | rate |
|---|---:|---:|---:|---:|
| `anchored_mayo` | 6 | 4 | 0 | 0.0000 |
| `unbound_mq` | 6 | 4 | 4096 | 1.0000 |

## Bonferroni decisions

- `mayo_baseline`: no flag
- `anchored_mayo`: no flag
- `synthetic_alg_anchor`: **SIGNIFICANT (anchor-correlation flag triggered)**