# AnchoredMAYO audit (tier toy, suite fast-v3)

`N_SEEDS=100`, `n=12`, `m=4`, `q=31`, family-wise α=0.001, Bonferroni threshold=2.38e-05.

## Per-target headline numbers

| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|---:|
| `mayo_baseline` | 4.00 | 12.00 | - | 0 | 0.158 | - |
| `anchored_mayo` | 4.00 | 12.00 | 1 | 0 | 0.158 | 0.871 |
| `synthetic_alg_anchor` | 4.00 | 12.00 | 1.4e-20 | 0 | 0.125 | 2.61e-59 |
| `synth_a_oilbasis` | 4.00 | 12.00 | 1 | 0 | 0.00255 | 0.00935 |
| `synth_b_hidden_idx` | 4.00 | 12.00 | 0.633 | 0 | 0.167 | 0.218 |
| `synth_c_rank1` | 4.00 | 12.00 | 1 | 0 | 0.117 | 0.789 |
| `synth_c_rank2` | 4.00 | 12.00 | 1 | 0 | 0.321 | 0.599 |
| `synth_c_rank4` | 4.00 | 12.00 | 0.000559 | 0 | 0.543 | 0.267 |

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