# AnchoredMAYO audit (tier l1-shaped, suite deep-v1)

`N_SEEDS=100`, `n=66`, `m=64`, `q=31`, family-wise α=0.001, Bonferroni threshold=1.72e-05.

## Per-target headline numbers (Fast tier)

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

## Per-target deep-tier numbers (P7 / P8)

| Target | P7 zero-block rate | P7 $p$-value | P8 best candidate | P8 match rate | P8 $p$-value |
|---|---:|---:|:---|---:|---:|
| `mayo_baseline` | - | - | - | - | - |
| `anchored_mayo` | 0 | 1.0 | trivial_i_mod_n | 0.0364 | 0.0603 |
| `synthetic_alg_anchor` | 0 | 1.0 | trivial_i_mod_n | 0.0516 | 2.32e-18 |
| `synth_a_oilbasis` | 1 | 0 | sha256_anchor_i | 0.0341 | 0.414 |
| `synth_b_hidden_idx` | 0 | 1.0 | shake_anchor_i | 1 | 0 |
| `synth_c_rank1` | 0 | 1.0 | shake_anchor_i | 0.0361 | 0.0824 |
| `synth_c_rank2` | 0 | 1.0 | trivial_i_mod_n | 0.0372 | 0.0256 |
| `synth_c_rank4` | 0 | 1.0 | xor_anchor_plus_i | 0.035 | 0.214 |

## P6 PKB-1 violation rates (toy-hash model)

| Mode | n_dpk_bits | n_tau_bits | violations | rate |
|---|---:|---:|---:|---:|
| `anchored_mayo` | 6 | 4 | 0 | 0.0000 |
| `unbound_mq` | 6 | 4 | 4096 | 1.0000 |

## Bonferroni decisions

- `mayo_baseline`: no flag
- `anchored_mayo`: no flag
- `synthetic_alg_anchor`: **SIGNIFICANT (P5 anchor-corr, P3 wedge)**
- `synth_a_oilbasis`: **SIGNIFICANT (P7 oil-basis)**
- `synth_b_hidden_idx`: **SIGNIFICANT (P8 hidden-idx)**
- `synth_c_rank1`: no flag
- `synth_c_rank2`: no flag
- `synth_c_rank4`: no flag