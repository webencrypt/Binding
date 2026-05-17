"""AnchoredMAYO audit suite (paper §7, Fast tier).

The suite implements pre-registered low-degree distinguisher probes P1, P2,
P4, P5, P6 against three targets:

* `mayo_baseline`           : a toy UOV-shaped public map (no anchor at all)
* `anchored_mayo`           : the same public map with a Class-B anchor
                              attached (the anchor data is *not* used in the
                              public map; the anchor only ever flows through
                              the transcript-binding tag)
* `synthetic_alg_anchor`    : a synthetic Class-C variant in which the anchor
                              data is fed into the oil-space basis of the
                              public map; the audit framework is expected to
                              detect structural leakage on this target.

Probe P3 (wedge product) and a more aggressive sweep across n in {24, 32}
sit in the standard / deep tiers and are not part of the Fast tier.
"""
