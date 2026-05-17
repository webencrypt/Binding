# AnchoredMAYO audit (tier l1-shaped, suite fast-v3)

`N_SEEDS=100`, `n=66`, `m=64`, `q=31`, family-wise α=0.001, Bonferroni threshold=2.38e-05.

## Per-target headline numbers

| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|---:|
| `mayo_baseline` | 64.00 | 66.00 | - | 0 | 0.17 | - |
| `anchored_mayo` | 64.00 | 66.00 | 0.0718 | 0 | 0.17 | 0.811 |
| `synthetic_alg_anchor` | 64.00 | 66.00 | 5.58e-20 | 0 | 0.176 | 2.61e-59 |
| `synth_a_oilbasis` | 64.00 | 66.00 | 1 | 0 | 0 | 0.025 |
| `synth_b_hidden_idx` | 64.00 | 66.00 | 1 | 0 | 0.201 | 0.71 |
| `synth_c_rank1` | 64.00 | 66.00 | 0.157 | 0 | 0.385 | 0.112 |
| `synth_c_rank2` | 64.00 | 66.00 | 1 | 0 | 0.841 | 0.066 |
| `synth_c_rank4` | 64.00 | 66.00 | 1 | 0 | 0.31 | 0.289 |

## P6 PKB-1 violation rates (toy-hash model)

| Mode | n_dpk_bits | n_tau_bits | violations | rate |
|---|---:|---:|---:|---:|
| `anchored_mayo` | 6 | 4 | 0 | 0.0000 |
| `unbound_mq` | 6 | 4 | 4096 | 1.0000 |

## Bonferroni decisions

- `mayo_baseline`: no flag
- `anchored_mayo`: no flag
- `synthetic_alg_anchor`: **SIGNIFICANT (P5 anchor-corr, P3 wedge)**
- `synth_a_oilbasis`: no flag
- `synth_b_hidden_idx`: no flag
- `synth_c_rank1`: no flag
- `synth_c_rank2`: no flag
- `synth_c_rank4`: no flag