# AnchoredMAYO audit (tier toy, suite deep-v1)

`N_SEEDS=50`, `n=12`, `m=4`, `q=31`, family-wise α=0.001, Bonferroni threshold=1.72e-05.

## Per-target headline numbers (Fast tier)

| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |
|---|---:|---:|---:|---:|---:|---:|
| `mayo_baseline` | 4.00 | 12.00 | - | 0 | 0.177 | - |
| `anchored_mayo` | 4.00 | 12.00 | 1 | 0 | 0.177 | 0.292 |
| `synthetic_alg_anchor` | 4.00 | 12.00 | 1.41e-09 | 0 | 0.229 | 8.82e-28 |
| `synth_a_oilbasis` | 4.00 | 12.00 | 1 | 0 | 0.0277 | 0.733 |
| `synth_b_hidden_idx` | 4.00 | 12.00 | 0.0302 | 0 | 0.156 | 0.48 |
| `synth_c_rank1` | 4.00 | 12.00 | 1 | 0 | 0.0729 | 0.51 |
| `synth_c_rank2` | 4.00 | 12.00 | 0.205 | 0 | 0.401 | 0.798 |
| `synth_c_rank4` | 4.00 | 12.00 | 0.0931 | 0 | 0.571 | 0.673 |

## Per-target deep-tier numbers (P7 / P8)

| Target | P7 zero-block rate | P7 $p$-value | P8 best candidate | P8 match rate | P8 $p$-value |
|---|---:|---:|:---|---:|---:|
| `mayo_baseline` | - | - | - | - | - |
| `anchored_mayo` | 0 | 1.0 | shake_anchor_i | 0.055 | 0.0687 |
| `synthetic_alg_anchor` | 0 | 1.0 | trivial_i_mod_n | 0.275 | 4.35e-84 |
| `synth_a_oilbasis` | 1 | 0 | sha256_anchor_i | 0.035 | 0.826 |
| `synth_b_hidden_idx` | 0 | 1.0 | shake_anchor_i | 1 | 0 |
| `synth_c_rank1` | 0 | 1.0 | sha256_anchor_i | 0.045 | 0.308 |
| `synth_c_rank2` | 0 | 1.0 | xor_anchor_plus_i | 0.055 | 0.0687 |
| `synth_c_rank4` | 0 | 1.0 | trivial_i_mod_n | 0.065 | 0.00877 |

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