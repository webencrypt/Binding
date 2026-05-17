#!/usr/bin/env python3
"""Top-level driver for the AnchoredMAYO audit (Fast / L1-shaped tiers).

Usage::

    .venv_exp/bin/python -m scripts.audit.run_audit              # Fast (toy)
    .venv_exp/bin/python -m scripts.audit.run_audit --tier l1    # L1-shaped
    .venv_exp/bin/python -m scripts.audit.run_audit --tier all   # both

The driver loads the pre-registered seed schedule, instantiates every
target factory (mayo_baseline, anchored_mayo, synthetic_alg_anchor) on each
seed, and runs probes P1, P2, P4, P5 across all targets plus probe P6 in
both `unbound` and `anchored_mayo` modes.  Output goes to
``reports/audit/audit_<tier>.json`` and to a one-screen Markdown summary at
``reports/audit/audit_<tier>_summary.md``.
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
from scripts.audit import targets as targets_mod  # noqa: E402
from scripts.audit import synth_variants  # noqa: E402
from scripts.audit import snova_like     # noqa: E402

N_SEEDS = 100
SUITE_VERSION = "fast-v3"  # bumped: tier-parameterised + synthetic variants + snova
DEEP_SUITE_VERSION = "deep-v1"  # P7 (oil-basis) + P8 (hidden-idx) registered


TIERS = {
    "toy": targets_mod.TIER_TOY,
    "l1":  targets_mod.TIER_L1,
}

SNOVA_TIERS = {
    "snova-toy": snova_like.SNOVA_TIER_TOY,
    "snova-l1":  snova_like.SNOVA_TIER_L1,
}


def get_factories(include_synth_variants: bool):
    """Combined factory map: canonical targets plus optional synthetic variants."""
    fac = dict(targets_mod.FACTORIES)
    if include_synth_variants:
        fac.update(synth_variants.SYNTH_VARIANT_FACTORIES)
    return fac


def run_for_target(name: str, factory, seeds: list, tier,
                   include_deep: bool = False) -> Dict:
    print(f"  building {name} targets ({len(seeds)} seeds, tier={tier.name})...",
          flush=True)
    t0 = time.time()
    tgts = [factory(s, tier) for s in seeds]
    elapsed_build = time.time() - t0
    out = {"target": name, "n_seeds": len(seeds), "build_seconds": elapsed_build}

    fast_probes = [
        (probes.probe_p1_macaulay,  "P1"),
        (probes.probe_p2_minrank,   "P2"),
        (probes.probe_p3_wedge,     "P3"),
        (probes.probe_p4_oilspace,  "P4"),
        (probes.probe_p5_battery,   "P5"),
    ]
    deep_probes = [
        (probes.probe_p7_oilbasis,   "P7"),
        (probes.probe_p8_hidden_idx, "P8"),
    ]
    probe_list = fast_probes + (deep_probes if include_deep else [])

    for fn, key in probe_list:
        t1 = time.time()
        out[key] = fn(tgts)
        out[key]["seconds"] = time.time() - t1
        print(f"    {key} done in {out[key]['seconds']:.2f}s", flush=True)
    return out


def run_tier(tier_name: str, n_seeds: int = N_SEEDS,
             include_synth_variants: bool = False,
             deep: bool = False) -> Dict:
    tier = TIERS[tier_name]
    out_dir = ROOT / "reports" / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds = targets_mod.make_seed_schedule(n_seeds,
                                           master=f"audit-{tier.name}-v3".encode())
    suite_label = DEEP_SUITE_VERSION if deep else SUITE_VERSION
    print(f"AnchoredMAYO audit (tier={tier.name}, suite={suite_label}, "
          f"N_SEEDS={n_seeds}, n={tier.n}, m={tier.m}, q={tier.q}, "
          f"variants={include_synth_variants}, deep={deep})")
    print(f"Pre-registered family-wise alpha = {probes.ALPHA}\n")

    suite: Dict = {
        "suite_version": suite_label,
        "tier":          tier.name,
        "n_seeds":       n_seeds,
        "alpha":         probes.ALPHA,
        "include_synth_variants": include_synth_variants,
        "deep_tier":     deep,
        "params":  {
            "n":  tier.n,
            "m":  tier.m,
            "q":  tier.q,
            "n_v": tier.n_v,
            "n_o": tier.n_o,
            "k_anchor": tier.k_anchor,
        },
        "targets": {},
        "p6": {},
    }

    factories = get_factories(include_synth_variants)
    for name, factory in factories.items():
        suite["targets"][name] = run_for_target(
            name, factory, seeds, tier, include_deep=deep
        )

    # P6 is target-agnostic (operates on a separate toy-hash model), shared
    # across tiers.  We still run it once per tier for reporting symmetry.
    print("\n  running P6 (toy PKB-1 exhaustive)...", flush=True)
    t0 = time.time()
    suite["p6"]["anchored_mayo"] = probes.probe_p6_pkb1_exhaustive(unbound=False)
    suite["p6"]["anchored_mayo"]["seconds"] = time.time() - t0
    print(f"    P6 anchored_mayo done in {suite['p6']['anchored_mayo']['seconds']:.2f}s",
          flush=True)
    t0 = time.time()
    suite["p6"]["unbound_mq"] = probes.probe_p6_pkb1_exhaustive(unbound=True)
    suite["p6"]["unbound_mq"]["seconds"] = time.time() - t0
    print(f"    P6 unbound_mq    done in {suite['p6']['unbound_mq']['seconds']:.2f}s",
          flush=True)

    # Final pass-fail decision: per-probe Bonferroni-corrected check.
    # Family-wise: 5 (Fast) or 7 (Deep) probes per target + 2 P6 modes, all
    # under alpha.
    decisions = {}
    probes_per_target = 7 if deep else 5
    n_probes = probes_per_target * len(suite["targets"]) + 2
    bonferroni_threshold = probes.ALPHA / n_probes

    for name, tdata in suite["targets"].items():
        p5 = tdata["P5"]
        p_anchor = p5.get("anchor_corr_pvalue")
        p3 = tdata["P3"]
        p_p3 = p3.get("bonferroni_p", None) if p3.get("anchor_required") is None else None
        d = {
            "P1_rank_mean":          tdata["P1"]["rank_mean"],
            "P3_bonferroni_p":       p_p3,
            "P5_pool_pvalue":        p5["pool_pvalue"],
            "P5_anchor_corr_pvalue": p_anchor,
            "anchor_corr_significant_at_FWER": (
                False if p_anchor is None else bool(p_anchor < bonferroni_threshold)
            ),
            "p3_significant_at_FWER": (
                False if p_p3 is None else bool(p_p3 < bonferroni_threshold)
            ),
        }
        if deep:
            p7 = tdata.get("P7", {})
            p8 = tdata.get("P8", {})
            p7_p = p7.get("pvalue")
            p8_p = p8.get("best_pvalue")
            p7_skipped = bool(p7.get("skipped"))
            p8_skipped = bool(p8.get("skipped"))
            d["P7_pvalue"] = None if p7_skipped else p7_p
            d["P7_zero_block_rate"] = p7.get("zero_block_rate")
            d["P8_best_pvalue"] = None if p8_skipped else p8_p
            d["P8_best_match_rate"] = p8.get("best_match_rate")
            d["p7_significant_at_FWER"] = (
                False if (p7_skipped or p7_p is None)
                else bool(p7_p < bonferroni_threshold)
            )
            d["p8_significant_at_FWER"] = (
                False if (p8_skipped or p8_p is None or
                          p8.get("best_match_rate", 0.0) < 0.95)
                else bool(p8_p < bonferroni_threshold)
            )
        decisions[name] = d

    suite["decisions"] = decisions
    suite["bonferroni_threshold"] = bonferroni_threshold

    suffix_parts = []
    if include_synth_variants:
        suffix_parts.append("variants")
    if deep:
        suffix_parts.append("deep_p7p8")
    suffix = "_" + "_".join(suffix_parts) if suffix_parts else ""

    json_path = out_dir / f"audit_{tier.name}{suffix}.json"
    with open(json_path, "w") as fh:
        json.dump(suite, fh, indent=2)
    print(f"\nwrote {json_path}")

    md = render_summary(suite)
    md_path = out_dir / f"audit_{tier.name}{suffix}_summary.md"
    md_path.write_text(md)
    print(f"wrote {md_path}\n")
    print(md)
    return suite


def render_summary(suite: Dict) -> str:
    deep = suite.get("deep_tier", False)
    lines = []
    lines.append(f"# AnchoredMAYO audit (tier {suite['tier']}, suite {suite['suite_version']})")
    lines.append("")
    lines.append(
        f"`N_SEEDS={suite['n_seeds']}`, "
        f"`n={suite['params']['n']}`, "
        f"`m={suite['params']['m']}`, "
        f"`q={suite['params']['q']}`, "
        f"family-wise α={suite['alpha']}, "
        f"Bonferroni threshold={suite['bonferroni_threshold']:.3g}.")
    lines.append("")
    lines.append("## Per-target headline numbers (Fast tier)")
    lines.append("")
    lines.append("| Target | P1 rank mean | P2 min-rank median | P3 Bonf $p$ | P4 vanish rate | P5 pool $p$ | P5 anchor-corr $p$ |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for name, t in suite["targets"].items():
        p4 = t["P4"]["rate_mean"]
        p5_pool = t["P5"]["pool_pvalue"]
        p5_anchor = t["P5"]["anchor_corr_pvalue"]
        p2 = t["P2"]["median_rank_mean"]
        p3 = t.get("P3", {})
        p3_b = p3.get("bonferroni_p")
        if p3.get("anchor_required"):
            p3_str = "-"
        else:
            p3_str = "-" if p3_b is None else f"{p3_b:.3g}"
        lines.append(
            f"| `{name}` | {t['P1']['rank_mean']:.2f} "
            f"| {p2:.2f} | {p3_str} | {p4:.4g} | {p5_pool:.3g} "
            f"| {('-' if p5_anchor is None else f'{p5_anchor:.3g}')} |"
        )
    lines.append("")

    if deep:
        lines.append("## Per-target deep-tier numbers (P7 / P8)")
        lines.append("")
        lines.append("| Target | P7 zero-block rate | P7 $p$-value | P8 best candidate | P8 match rate | P8 $p$-value |")
        lines.append("|---|---:|---:|:---|---:|---:|")
        for name, t in suite["targets"].items():
            p7 = t.get("P7", {})
            p8 = t.get("P8", {})
            if p7.get("skipped"):
                p7_zb, p7_p = "-", "-"
            else:
                p7_zb = f"{p7.get('zero_block_rate', 0.0):.3g}"
                p7_p_val = p7.get("pvalue", 1.0)
                p7_p = f"{p7_p_val:.3g}" if p7_p_val < 1.0 else "1.0"
            if p8.get("skipped"):
                p8_cand, p8_rate, p8_p = "-", "-", "-"
            else:
                p8_cand = p8.get("best_candidate", "-") or "-"
                p8_rate = f"{p8.get('best_match_rate', 0.0):.3g}"
                p8_p_val = p8.get("best_pvalue", 1.0)
                p8_p = f"{p8_p_val:.3g}" if p8_p_val < 1.0 else "1.0"
            lines.append(
                f"| `{name}` | {p7_zb} | {p7_p} | {p8_cand} | {p8_rate} | {p8_p} |"
            )
        lines.append("")

    lines.append("## P6 PKB-1 violation rates (toy-hash model)")
    lines.append("")
    lines.append("| Mode | n_dpk_bits | n_tau_bits | violations | rate |")
    lines.append("|---|---:|---:|---:|---:|")
    for mode in ["anchored_mayo", "unbound_mq"]:
        r = suite["p6"][mode]
        lines.append(
            f"| `{mode}` | {r['n_dpk_bits']} | {r['n_tau_bits']} | {r['violations']} | {r['violation_rate']:.4f} |"
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
        if d.get("p7_significant_at_FWER"):
            flags.append("P7 oil-basis")
        if d.get("p8_significant_at_FWER"):
            flags.append("P8 hidden-idx")
        flag_str = (
            "**SIGNIFICANT (" + ", ".join(flags) + ")**"
            if flags else "no flag"
        )
        lines.append(f"- `{name}`: {flag_str}")
    return "\n".join(lines)


def run_snova_tier(tier_name: str, n_seeds: int = N_SEEDS) -> Dict:
    """Run the SNOVA-like cross-family audit at the given tier."""
    tier = SNOVA_TIERS[tier_name]
    out_dir = ROOT / "reports" / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds = targets_mod.make_seed_schedule(
        n_seeds, master=f"audit-{tier.name}-v3".encode()
    )
    print(f"SNOVA-like audit (tier={tier.name}, suite={SUITE_VERSION}, "
          f"N_SEEDS={n_seeds}, n={tier.n}, m={tier.m}, q={tier.q}, "
          f"nb_v={tier.nb_v}, nb_o={tier.nb_o})")
    print(f"Pre-registered family-wise alpha = {probes.ALPHA}\n")

    suite: Dict = {
        "suite_version": SUITE_VERSION,
        "tier":          tier.name,
        "family":        "snova-like",
        "n_seeds":       n_seeds,
        "alpha":         probes.ALPHA,
        "params":  {
            "n":  tier.n,
            "m":  tier.m,
            "q":  tier.q,
            "nb_v": tier.nb_v,
            "nb_o": tier.nb_o,
            "block_size": tier.block_size,
            "k_anchor": tier.k_anchor,
        },
        "targets": {},
        "p6": {},
    }

    for name, factory in snova_like.SNOVA_LIKE_FACTORIES.items():
        suite["targets"][name] = run_for_target(name, factory, seeds, tier)

    print("\n  running P6 (toy PKB-1 exhaustive)...", flush=True)
    t0 = time.time()
    suite["p6"]["anchored_mayo"] = probes.probe_p6_pkb1_exhaustive(unbound=False)
    suite["p6"]["anchored_mayo"]["seconds"] = time.time() - t0
    t0 = time.time()
    suite["p6"]["unbound_mq"] = probes.probe_p6_pkb1_exhaustive(unbound=True)
    suite["p6"]["unbound_mq"]["seconds"] = time.time() - t0

    decisions = {}
    n_probes = 5 * len(suite["targets"]) + 2
    bonferroni_threshold = probes.ALPHA / n_probes
    for name, tdata in suite["targets"].items():
        p5 = tdata["P5"]
        p_anchor = p5.get("anchor_corr_pvalue")
        p3 = tdata["P3"]
        p_p3 = p3.get("bonferroni_p", None) if p3.get("anchor_required") is None else None
        decisions[name] = {
            "P1_rank_mean":          tdata["P1"]["rank_mean"],
            "P3_bonferroni_p":       p_p3,
            "P5_pool_pvalue":        p5["pool_pvalue"],
            "P5_anchor_corr_pvalue": p_anchor,
            "anchor_corr_significant_at_FWER": (
                False if p_anchor is None else bool(p_anchor < bonferroni_threshold)
            ),
            "p3_significant_at_FWER": (
                False if p_p3 is None else bool(p_p3 < bonferroni_threshold)
            ),
        }
    suite["decisions"] = decisions
    suite["bonferroni_threshold"] = bonferroni_threshold

    json_path = out_dir / f"audit_{tier.name}.json"
    with open(json_path, "w") as fh:
        json.dump(suite, fh, indent=2)
    print(f"\nwrote {json_path}")

    md = render_summary(suite)
    md_path = out_dir / f"audit_{tier.name}_summary.md"
    md_path.write_text(md)
    print(f"wrote {md_path}\n")
    print(md)
    return suite


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier", choices=["toy", "l1", "all",
                                           "snova-toy", "snova-l1", "snova-all"],
                        default="toy",
                        help="audit tier to run (default: toy)")
    parser.add_argument("--n-seeds", type=int, default=N_SEEDS,
                        help=f"number of seeds (default: {N_SEEDS})")
    parser.add_argument("--variants", action="store_true",
                        help="include synthetic variants A/B/C in the run")
    parser.add_argument("--deep", action="store_true",
                        help="enable Deep tier: register P7 (oil-basis) and "
                             "P8 (hidden-idx) probes")
    args = parser.parse_args()

    if args.tier == "all":
        for t in ["toy", "l1"]:
            run_tier(t, args.n_seeds, args.variants, deep=args.deep)
    elif args.tier == "snova-all":
        for t in ["snova-toy", "snova-l1"]:
            run_snova_tier(t, args.n_seeds)
    elif args.tier in SNOVA_TIERS:
        run_snova_tier(args.tier, args.n_seeds)
    else:
        run_tier(args.tier, args.n_seeds, args.variants, deep=args.deep)


if __name__ == "__main__":
    main()
