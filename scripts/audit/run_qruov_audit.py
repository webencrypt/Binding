#!/usr/bin/env python3
"""Cross-family audit driver: QR-UOV-shape targets.

Mirrors ``run_audit.py``'s structure but instantiates QR-UOV-shape
factories (modulus polynomial as anchor) on the seed schedule and runs
the Fast-tier probes (P1, P2, P3, P4, P5) against each target.

Usage::

    python3 -m scripts.audit.run_qruov_audit              # toy tier
    python3 -m scripts.audit.run_qruov_audit --tier l1    # L1-shape tier
    python3 -m scripts.audit.run_qruov_audit --n-seeds 50 # custom

Output goes to::

    reports/audit/qruov_audit_<tier>.json
    reports/audit/qruov_audit_<tier>_summary.md
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.audit import probes              # noqa: E402
from scripts.audit import qr_uov_like as qruov # noqa: E402
from scripts.audit import targets as targets_mod  # noqa: E402

N_SEEDS_DEFAULT = 100
SUITE_VERSION = "qruov-fast-v1"

QRUOV_TIERS = {
    "toy": qruov.QRUOV_TIER_TOY,
    "l1":  qruov.QRUOV_TIER_L1,
}


def run_for_target(name: str, factory, seeds: list, tier) -> Dict:
    print(f"  building {name} targets ({len(seeds)} seeds, tier={tier.name})...",
          flush=True)
    t0 = time.time()
    tgts = [factory(s, tier) for s in seeds]
    elapsed_build = time.time() - t0
    out = {"target": name, "n_seeds": len(seeds),
           "build_seconds": elapsed_build}

    probe_list = [
        (probes.probe_p1_macaulay,  "P1"),
        (probes.probe_p2_minrank,   "P2"),
        (probes.probe_p3_wedge,     "P3"),
        (probes.probe_p4_oilspace,  "P4"),
        (probes.probe_p5_battery,   "P5"),
    ]
    for fn, key in probe_list:
        t1 = time.time()
        out[key] = fn(tgts)
        out[key]["seconds"] = time.time() - t1
        print(f"    {key} done in {out[key]['seconds']:.2f}s", flush=True)
    return out


def run_tier(tier_name: str, n_seeds: int = N_SEEDS_DEFAULT) -> Dict:
    tier = QRUOV_TIERS[tier_name]
    out_dir = ROOT / "reports" / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds = targets_mod.make_seed_schedule(
        n_seeds, master=f"audit-qruov-{tier.name}-v1".encode(),
    )
    print(f"QR-UOV-shape audit (tier={tier.name}, suite={SUITE_VERSION}, "
          f"N_SEEDS={n_seeds}, n={tier.n}, m={tier.m}, q={tier.q}, "
          f"d_g={tier.d_g}, nL_v={tier.nL_v}, nL_o={tier.nL_o})")
    print(f"Pre-registered family-wise alpha = {probes.ALPHA}\n")

    suite: Dict = {
        "suite_version": SUITE_VERSION,
        "family":        "qr_uov_like",
        "tier":          tier.name,
        "n_seeds":       n_seeds,
        "alpha":         probes.ALPHA,
        "params": {
            "n":    tier.n,
            "m":    tier.m,
            "q":    tier.q,
            "n_v":  tier.n_v,
            "n_o":  tier.n_o,
            "d_g":  tier.d_g,
            "nL_v": tier.nL_v,
            "nL_o": tier.nL_o,
            "k_anchor": tier.k_anchor,
        },
        "targets": {},
    }

    for name, factory in qruov.QRUOV_LIKE_FACTORIES.items():
        suite["targets"][name] = run_for_target(name, factory, seeds, tier)

    # Bonferroni-corrected decisions over the QR-UOV family
    # 5 probes per target * n_targets, single-family alpha.
    n_probes = 5 * len(suite["targets"])
    bonferroni_threshold = probes.ALPHA / n_probes
    decisions = {}
    for name, tdata in suite["targets"].items():
        p3 = tdata["P3"]
        p_p3 = p3.get("bonferroni_p", None) if not p3.get("anchor_required") else None
        p_anchor = tdata["P5"].get("anchor_corr_pvalue")
        d = {
            "P1_rank_mean":          tdata["P1"]["rank_mean"],
            "P2_median_rank_mean":   tdata["P2"]["median_rank_mean"],
            "P3_bonferroni_p":       p_p3,
            "P5_pool_pvalue":        tdata["P5"]["pool_pvalue"],
            "P5_anchor_corr_pvalue": p_anchor,
            "p3_significant_at_FWER": (
                False if p_p3 is None else bool(p_p3 < bonferroni_threshold)
            ),
            "anchor_corr_significant_at_FWER": (
                False if p_anchor is None else bool(p_anchor < bonferroni_threshold)
            ),
        }
        decisions[name] = d

    suite["decisions"] = decisions
    suite["bonferroni_threshold"] = bonferroni_threshold

    json_path = out_dir / f"qruov_audit_{tier.name}.json"
    with open(json_path, "w") as fh:
        json.dump(suite, fh, indent=2)
    print(f"\nwrote {json_path}")

    md = render_summary(suite)
    md_path = out_dir / f"qruov_audit_{tier.name}_summary.md"
    md_path.write_text(md)
    print(f"wrote {md_path}\n")
    print(md)
    return suite


def render_summary(suite: Dict) -> str:
    lines = []
    lines.append(
        f"# QR-UOV-shape audit (tier {suite['tier']}, "
        f"suite {suite['suite_version']})"
    )
    lines.append("")
    lines.append(
        f"`N_SEEDS={suite['n_seeds']}`, "
        f"`n={suite['params']['n']}`, "
        f"`m={suite['params']['m']}`, "
        f"`q={suite['params']['q']}`, "
        f"`d_g={suite['params']['d_g']}`, "
        f"family-wise α={suite['alpha']}, "
        f"Bonferroni threshold={suite['bonferroni_threshold']:.3g}.")
    lines.append("")
    lines.append(
        "Anchor = monic ``g(y)`` coefficients, ascending (constant term first; "
        "leading 1 included as last byte).  ``g(y)`` is **algebraically "
        "consumed** by every multiplication in ``L``, putting plain QR-UOV "
        "into the high-risk anchor class of our taxonomy (Class C)."
    )
    lines.append("")
    lines.append("## Per-target headline numbers")
    lines.append("")
    lines.append(
        "| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ "
        "| P5 pool $p$ | P5 anchor-corr $p$ |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|")
    for name, t in suite["targets"].items():
        p5_pool = t["P5"]["pool_pvalue"]
        p5_anchor = t["P5"]["anchor_corr_pvalue"]
        p2 = t["P2"]["median_rank_mean"]
        p3 = t.get("P3", {})
        p3_b = p3.get("bonferroni_p")
        p3_str = "-" if p3_b is None else f"{p3_b:.3g}"
        lines.append(
            f"| `{name}` | {t['P1']['rank_mean']:.2f} | {p2:.2f} | "
            f"{p3_str} | {p5_pool:.3g} | "
            f"{('-' if p5_anchor is None else f'{p5_anchor:.3g}')} |"
        )
    lines.append("")
    lines.append("## Bonferroni decisions")
    lines.append("")
    for name, d in suite["decisions"].items():
        flags = []
        if d.get("anchor_corr_significant_at_FWER"):
            flags.append("P5 anchor-corr")
        if d.get("p3_significant_at_FWER"):
            flags.append("P3 wedge")
        flag_str = (
            "**SIGNIFICANT (" + ", ".join(flags) + ")**" if flags
            else "no flag"
        )
        lines.append(f"- `{name}`: {flag_str}")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "- `qruov_baseline` is the canonical QR-UOV shape with a fresh "
        "irreducible ``g(y)`` per seed.  A flag here would indicate that "
        "the modulus *as it varies across the deployment family* leaks "
        "structurally into the public map -- a finding worth reporting "
        "on the QR-UOV family."
    )
    lines.append(
        "- `qruov_synth_sparse_g` simulates a *weak modulus* regime "
        "(two-term ``g(y)``).  Flagging this confirms the audit framework's "
        "structural sensitivity matches the Lin--Wang 2024 detection signal "
        "on sparse-modulus QR-UOV; failing to flag is a calibration result."
    )
    lines.append(
        "- `qruov_synth_pinned_g` is a unit test: the framework MUST flag it."
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=list(QRUOV_TIERS.keys()) + ["all"],
                        default="toy",
                        help="Audit tier (default: toy).")
    parser.add_argument("--n-seeds", type=int, default=N_SEEDS_DEFAULT,
                        help=f"Number of seeds (default: {N_SEEDS_DEFAULT}).")
    args = parser.parse_args()

    if args.tier == "all":
        for tn in QRUOV_TIERS:
            run_tier(tn, args.n_seeds)
    else:
        run_tier(args.tier, args.n_seeds)


if __name__ == "__main__":
    main()
