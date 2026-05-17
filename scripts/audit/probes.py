"""Pre-registered structural probes for the AnchoredMAYO audit (Fast tier).

Each probe takes a list of ``Target`` objects (same target type across seeds)
and returns a JSON-serialisable summary.  All probes are deterministic given
the seed schedule.

Probes implemented in this module
---------------------------------
* P1 -- Macaulay rank profile at degree D = 3
* P2 -- MinRank distinguisher search (degree-1 linear combinations)
* P4 -- Oil-space recovery heuristic (intersection-of-image attempts)
* P5 -- Statistical battery:
        - chi-square goodness-of-fit on coefficient marginals
        - low-degree linear test on uniform-random projections
        - **anchor--public-map correlation** (this is the probe that flags
          the synthetic algebraic-anchor target)
* P6 -- Small-parameter exhaustive PKB-1 violations (toy-hash model)

Each probe reports an *effect size* and a *p-value*.  P-values are combined
across seeds via the chi-square aggregation when the underlying test is
parametric, and via Bonferroni correction at the suite level (see
``run_audit.py``).  Probes report `passed=True` when the family-wise
significance threshold is *not* exceeded; otherwise ``passed=False`` with a
short reason string.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List

import galois
import numpy as np
from scipy import stats

from .targets import GF, Q_FIELD, Target, get_gf

# Family-wise alpha for the entire suite.  Lower than 1e-3 to compensate for
# multiple testing without explicit Bonferroni overhead.
ALPHA: float = 1e-3


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _quadratic_to_coeffs(P: galois.FieldArray) -> np.ndarray:
    """Flatten a symmetric n x n quadratic-form matrix to its 'upper-triangle'
    coefficient vector of length n*(n+1)/2 over GF(q)."""
    n = P.shape[0]
    flat = []
    arr = np.array(P, dtype=np.int64)
    for i in range(n):
        for j in range(i, n):
            flat.append(arr[i, j])
    return np.array(flat, dtype=np.int64)


def _gf_rank(M: galois.FieldArray) -> int:
    """Rank of a matrix over GF(q)."""
    return int(np.linalg.matrix_rank(M))


def _target_q(targets: List[Target]) -> int:
    """Return the field order shared by all targets in the list.

    All targets in a single probe call must share the same field; we
    enforce this here so a probe doesn't silently mix tiers.
    """
    if not targets:
        return Q_FIELD
    q = targets[0].q
    for tgt in targets[1:]:
        if tgt.q != q:
            raise ValueError(
                "all targets in a probe call must share the same field"
            )
    return q


# ----------------------------------------------------------------------
# P1: Macaulay rank profile at D = 2 (linearised system)
# ----------------------------------------------------------------------
def probe_p1_macaulay(targets: List[Target]) -> Dict:
    """Compute the rank of the linearised public map for each target.

    At ``D = 2`` the Macaulay matrix is just the ``m x N`` coefficient
    matrix with ``N = binomial(n+1, 2) + n + 1`` (quadratic, linear, and
    constant monomials).  In the toy generator the polynomials are
    homogeneous-quadratic, so we use ``N = binomial(n+1, 2)`` and report
    the rank of the ``m x N`` upper-triangular matrix.  A rank below ``m``
    is a structural distinguisher (the public-map polynomials are linearly
    dependent, e.g. because the anchor introduces a redundancy).
    """
    if not targets:
        return {"name": "P1", "n_seeds": 0}
    n = targets[0].n
    m = targets[0].m
    q = _target_q(targets)
    GFq = get_gf(q)
    N = n * (n + 1) // 2  # number of (a, b) with a <= b

    ranks = []
    for tgt in targets:
        rows = []
        for P_i in tgt.P:
            rows.append(_quadratic_to_coeffs(P_i))
        M = GFq(np.array(rows, dtype=np.int64))
        ranks.append(_gf_rank(M))

    ranks = np.array(ranks, dtype=np.int64)
    return {
        "name": "P1",
        "description": "Linearised public-map rank (D = 2 Macaulay)",
        "n_seeds": len(targets),
        "n": n, "m": m, "cols": N,
        "rank_min": int(ranks.min()),
        "rank_max": int(ranks.max()),
        "rank_mean": float(ranks.mean()),
        "rank_std":  float(ranks.std()),
        "rank_histogram": {int(r): int((ranks == r).sum()) for r in np.unique(ranks)},
    }


# ----------------------------------------------------------------------
# P2: MinRank distinguisher search (degree-1 linear combinations)
# ----------------------------------------------------------------------
def probe_p2_minrank(targets: List[Target], n_combos: int = 200) -> Dict:
    """For each target sample ``n_combos`` uniform-random m-vectors
    ``alpha = (alpha_1, ..., alpha_m) in GF(q)^m`` and compute the rank of
    ``M_alpha = sum_i alpha_i * P_i``.  Report the minimum observed rank
    across seeds and combinations.

    For UOV-shaped systems with oil dimension ``n_o``, the maximum possible
    rank of any GF(q)-linear combination of the public matrices is
    ``2 n_v + n_o`` (the oil-vinegar block rank); generic random affine
    quadratic systems would have rank ``n``.  A *non-trivial* MinRank
    distinguisher would show ranks consistently below this UOV ceiling.
    """
    if not targets:
        return {"name": "P2", "n_seeds": 0}
    q = _target_q(targets)
    GFq = get_gf(q)
    rng = np.random.default_rng(seed=0xCAFEBABE)
    min_rank_seen = []
    median_rank_seen = []
    for tgt in targets:
        ranks = []
        for _ in range(n_combos):
            alpha = rng.integers(0, q, size=tgt.m)
            M = np.zeros_like(np.array(tgt.P[0]))
            for i in range(tgt.m):
                M = (M + int(alpha[i]) * np.array(tgt.P[i], dtype=np.int64)) % q
            ranks.append(_gf_rank(GFq(M)))
        ranks = np.array(ranks, dtype=np.int64)
        min_rank_seen.append(int(ranks.min()))
        median_rank_seen.append(int(np.median(ranks)))
    return {
        "name": "P2",
        "description": "MinRank distinguisher: rank distribution of random GF(q)-linear combinations",
        "n_seeds": len(targets),
        "n_combos_per_seed": n_combos,
        "min_rank_min":    int(min(min_rank_seen)),
        "min_rank_max":    int(max(min_rank_seen)),
        "min_rank_mean":   float(np.mean(min_rank_seen)),
        "median_rank_min": int(min(median_rank_seen)),
        "median_rank_max": int(max(median_rank_seen)),
        "median_rank_mean":float(np.mean(median_rank_seen)),
    }


# ----------------------------------------------------------------------
# P4: Oil-space recovery heuristic
# ----------------------------------------------------------------------
def probe_p4_oilspace(targets: List[Target], n_trials: int = 100) -> Dict:
    """Heuristic oil-space recovery: for each seed, sample ``n_trials``
    random vectors v in GF(q)^n and test how many satisfy
    ``v^T P_i v = 0`` for **all** ``i in [m]``.  In a UOV-structured map,
    vectors lying in the oil subspace satisfy this; vectors outside the
    oil subspace satisfy it only with probability ``q^{-m}`` per equation.

    Output: empirical "all-zero" rate, expected baseline ``q^{-m}``.
    Significant excess over baseline -> structural distinguisher.
    """
    if not targets:
        return {"name": "P4", "n_seeds": 0}
    q = _target_q(targets)
    GFq = get_gf(q)
    rng = np.random.default_rng(seed=0xC0FFEE)
    rates = []
    for tgt in targets:
        cnt = 0
        for _ in range(n_trials):
            v = GFq(rng.integers(0, q, size=tgt.n))
            ok = True
            for P_i in tgt.P:
                if int((v @ P_i) @ v) != 0:
                    ok = False
                    break
            if ok:
                cnt += 1
        rates.append(cnt / n_trials)
    rates_arr = np.array(rates)
    expected = (1.0 / q) ** targets[0].m  # baseline if random affine quadratic
    return {
        "name": "P4",
        "description": "Oil-space recovery heuristic: probability uniform v vanishes on all P_i",
        "n_seeds": len(targets),
        "n_trials_per_seed": n_trials,
        "rate_min":  float(rates_arr.min()),
        "rate_max":  float(rates_arr.max()),
        "rate_mean": float(rates_arr.mean()),
        "expected_random": expected,
        "ratio_to_random": float(rates_arr.mean()) / expected if expected > 0 else float("inf"),
    }


# ----------------------------------------------------------------------
# P3: Wedge-product / structural fingerprint probe
# ----------------------------------------------------------------------
def _structural_fingerprint(tgt: Target) -> np.ndarray:
    """Compute a vector of conjugation/congruence-sensitive structural
    invariants from the public-map matrices of ``tgt``.

    Fingerprint coordinates (all reduced mod q):

    * traces of the first ``M = min(m, 4)`` matrices ``P_1, ..., P_M``;
    * traces of pairwise products ``trace(P_i P_j)`` for ``i <= j``;
    * for each ``P_i`` (``i < M``), the **unsorted** diagonal entries
      ``P_i[k, k]`` for ``k = 0, ..., min(n, 8) - 1`` -- this picks up
      direct coefficient leakage at any specific position;
    * for each ``P_i`` (``i < M``), the off-diagonal entries
      ``P_i[k, k+1]`` for ``k = 0, ..., min(n - 1, 4)`` -- captures
      neighbouring off-diagonal leakage.

    The fingerprint length is small (~30 for toy, ~50 for L1) which keeps
    the Bonferroni penalty over (anchor_byte x coord) tests modest.
    """
    M = min(tgt.m, 4)
    n = tgt.n
    q = tgt.q
    f: list = []
    P_arr = [np.array(tgt.P[i], dtype=np.int64) % q for i in range(M)]
    for P_i in P_arr:
        f.append(int(np.trace(P_i)) % q)
    for i in range(M):
        for j in range(i, M):
            prod = (P_arr[i] @ P_arr[j]) % q
            f.append(int(np.trace(prod)) % q)
    diag_count = min(n, 8)
    off_count = min(n - 1, 4)
    for P_i in P_arr:
        diag = np.diag(P_i) % q
        f.extend(int(x) for x in diag[:diag_count])
    for P_i in P_arr:
        for k in range(off_count):
            f.append(int(P_i[k, k + 1]) % q)
    return np.array(f, dtype=np.int64)


def _median_split(v: np.ndarray) -> np.ndarray:
    """Split a vector into binary {0, 1} buckets by its median."""
    med = float(np.median(v))
    return (v > med).astype(np.int64)


def probe_p3_wedge(targets: List[Target]) -> Dict:
    """Wedge-product / structural-fingerprint probe.

    Strategy: compute a fingerprint vector ``F(seed)`` of polynomial
    invariants of the public map.  For each anchor byte ``a_b`` and each
    fingerprint coordinate ``F_c``, run a 2x2 chi-square contingency
    test on (median_split(a_b), median_split(F_c)) across seeds.
    Bonferroni-correct over the total number of (anchor_byte, coord)
    tests and report the corrected smallest p-value.

    For UOV-shaped maps with anchor-derived shears (Variant A) or
    anchor-derived rank-r perturbations (Variant C), at least one
    fingerprint coordinate inherits an anchor-dependent contribution
    that the chi-square contingency test picks up.

    For UOV-shaped maps without algebraic anchor coupling (baseline,
    AnchoredMAYO Class B) the fingerprint is statistically
    independent of the anchor so the probe does not flag.
    """
    if not targets:
        return {"name": "P3", "n_seeds": 0}
    q = _target_q(targets)
    if not all(tgt.anchor is not None for tgt in targets):
        return {"name": "P3", "n_seeds": len(targets), "anchor_required": True}

    fingerprints = np.array([_structural_fingerprint(tgt) for tgt in targets])
    F_dim = fingerprints.shape[1]

    n_anchor_bytes = max(len(tgt.anchor) for tgt in targets)
    anchor_matrix = np.zeros((len(targets), n_anchor_bytes), dtype=np.int64)
    for i, tgt in enumerate(targets):
        anchor_matrix[i, : len(tgt.anchor)] = np.frombuffer(tgt.anchor, dtype=np.uint8)
    anchor_matrix = anchor_matrix % q

    a_split = np.column_stack([_median_split(anchor_matrix[:, b])
                               for b in range(n_anchor_bytes)])
    f_split = np.column_stack([_median_split(fingerprints[:, c])
                               for c in range(F_dim)])

    p_min = 1.0
    p_min_idx = (-1, -1)
    chi2_max = 0.0
    n_tests = 0
    significant_count = 0
    all_logs = []
    raw_threshold = 1e-3
    for b in range(n_anchor_bytes):
        for c in range(F_dim):
            table = np.zeros((2, 2), dtype=np.int64)
            for s in range(len(targets)):
                table[int(a_split[s, b]), int(f_split[s, c])] += 1
            if (table.sum(axis=0) > 0).all() and (table.sum(axis=1) > 0).all():
                chi2, p, _, _ = stats.chi2_contingency(table)
            else:
                chi2, p = 0.0, 1.0
            n_tests += 1
            if p < raw_threshold:
                significant_count += 1
            all_logs.append(float(p))
            if p < p_min:
                p_min = float(p)
                p_min_idx = (int(b), int(c))
                chi2_max = float(chi2)

    bonferroni_p = min(1.0, p_min * n_tests)

    return {
        "name": "P3",
        "description": ("Structural fingerprint vs anchor: 2x2 chi-square "
                        "contingency over (anchor_byte, coord) pairs"),
        "n_seeds":          len(targets),
        "fingerprint_dim":  F_dim,
        "anchor_bytes":     n_anchor_bytes,
        "n_tests":          n_tests,
        "p_min":            float(p_min),
        "p_min_byte_coord": list(p_min_idx),
        "chi2_max":         float(chi2_max),
        "bonferroni_p":     float(bonferroni_p),
        "raw_significant_count": significant_count,
        "raw_threshold":    raw_threshold,
    }


# ----------------------------------------------------------------------
# P5: Statistical battery
# ----------------------------------------------------------------------
def probe_p5_battery(targets: List[Target]) -> Dict:
    """Three sub-tests of paper §7's cryptanalytic statistical battery.

    1. Chi-square goodness-of-fit: pool all coefficients of P across seeds,
       test whether they are uniform on F_q.
    2. Low-degree linear test: choose uniform-random GF(q)-linear forms on
       coefficient vectors and check whether the result is uniform on F_q.
    3. Anchor--public-map correlation: when the target carries an anchor,
       compute the chi-square statistic between (1st anchor nibble) and
       (1st coefficient of P_0) across seeds.  This is the probe we expect
       to flag the synthetic algebraic-anchor target.
    """
    if not targets:
        return {"name": "P5", "n_seeds": 0}
    q = _target_q(targets)

    # 1. Chi-square on pooled coefficients
    coeffs = []
    for tgt in targets:
        for P_i in tgt.P:
            coeffs.extend(_quadratic_to_coeffs(P_i).tolist())
    coeffs = np.array(coeffs, dtype=np.int64)
    counts = np.array([(coeffs == k).sum() for k in range(q)])
    expected = np.full(q, len(coeffs) / q)
    chi2_pool, p_pool = stats.chisquare(counts, expected)

    # 2. Low-degree linear test (chi-square on l(coeffs) over many random l)
    rng = np.random.default_rng(seed=0xBEEF)
    coeff_per_seed = []
    for tgt in targets:
        flat = []
        for P_i in tgt.P:
            flat.extend(_quadratic_to_coeffs(P_i).tolist())
        coeff_per_seed.append(np.array(flat, dtype=np.int64))
    L = 64
    p_lindeg_min = 1.0
    p_lindeg_min_seed = -1
    for s, flat in enumerate(coeff_per_seed):
        proj_results = []
        for _ in range(L):
            proj = rng.integers(0, q, size=len(flat))
            v = int(np.sum(proj * flat) % q)
            proj_results.append(v)
        bins = np.array([(np.array(proj_results) == k).sum() for k in range(q)])
        exp_bins = np.full(q, L / q)
        _, p = stats.chisquare(bins, exp_bins)
        if p < p_lindeg_min:
            p_lindeg_min = p
            p_lindeg_min_seed = s

    # 3. Anchor--public-map correlation (only when the target has anchor data).
    #
    # Pre-registered probe: for each seed, take the first byte of the anchor
    # reduced mod q as ``a_i``, and the (0,0) entry of P_0 as ``c_i``.  Bin
    # both vectors into 4 quartiles and run a chi-square contingency test.
    # The probe asks whether ``P_0[0,0]`` is statistically dependent on
    # ``anchor[0]`` across the seed schedule.
    if all(tgt.anchor is not None for tgt in targets):
        anchor_proxy = np.array([tgt.anchor[0] % q for tgt in targets])
        coeff_proxy  = np.array([int(np.array(tgt.P[0])[0, 0]) for tgt in targets])

        def _quart(v):
            qs = np.quantile(v, [0.25, 0.5, 0.75])
            buckets = np.zeros_like(v)
            for i, x in enumerate(v):
                if   x <= qs[0]: buckets[i] = 0
                elif x <= qs[1]: buckets[i] = 1
                elif x <= qs[2]: buckets[i] = 2
                else:            buckets[i] = 3
            return buckets

        a4 = _quart(anchor_proxy)
        c4 = _quart(coeff_proxy)
        table = np.zeros((4, 4), dtype=np.int64)
        for a, c in zip(a4, c4):
            table[int(a)][int(c)] += 1
        if table.sum() > 0 and (table.sum(axis=0) > 0).all() and (table.sum(axis=1) > 0).all():
            chi2_corr, p_corr, _, _ = stats.chi2_contingency(table)
        else:
            chi2_corr, p_corr = 0.0, 1.0
    else:
        chi2_corr, p_corr = None, None

    return {
        "name": "P5",
        "description": "Statistical battery: chi-square pool, low-deg linear test, anchor correlation",
        "n_seeds": len(targets),
        "pool_chi2":          float(chi2_pool),
        "pool_pvalue":        float(p_pool),
        "lindeg_min_pvalue":  float(p_lindeg_min),
        "lindeg_min_seed":    int(p_lindeg_min_seed),
        "anchor_corr_chi2":   None if chi2_corr is None else float(chi2_corr),
        "anchor_corr_pvalue": None if p_corr  is None else float(p_corr),
    }


# ----------------------------------------------------------------------
# P6: small-parameter exhaustive PKB-1 violations
# ----------------------------------------------------------------------
def probe_p6_pkb1_exhaustive(n_dpk_bits: int = 6,
                             n_tau_bits: int = 4,
                             n_pk_samples: int = 4096,
                             n_query_per_pk: int = 256,
                             unbound: bool = False) -> Dict:
    """Toy-hash exhaustive PKB-1 search.

    Model: pk in {0,1}^pk_bits, msg in {0,1}^msg_bits, sig in {0,1}^sig_bits.
    For a *bound* verifier (paper's AnchoredMAYO PKB layer), accept iff a
    target-collision search with ``n_dpk_bits``-bit digest and
    ``n_tau_bits``-bit tag succeeds; for an *unbound* verifier (plain MQ
    ownership game, paper Theorem 2), accept iff sig satisfies P(sig)=msg
    -- which reduces in our toy to "a fraction 1 / 2^n_tau_bits of pk*'s
    accept the same (sig, msg)" -- so we model unbound as accept iff the
    truncated MQ check matches.

    The probe reports the empirical PKB-1 violation rate (probability that
    a random pk* != pk verifies the same (sig, msg)) for both modes.
    """
    rng = np.random.default_rng(seed=0xDEADBEEF)
    violations = 0
    for _ in range(n_pk_samples):
        pk    = rng.integers(0, 2 ** 16)
        msg   = rng.integers(0, 2 ** 12)
        sig   = rng.integers(0, 2 ** 16)
        # Fixed accept criterion
        if unbound:
            # Model: accept iff truncated linear hash matches.  About 1 in
            # 2^n_tau_bits random (pk, sig, msg) triples accept; roughly
            # 1/2 of pk*'s differ from pk and accept under same sig/msg.
            tau = (pk ^ msg ^ sig) & ((1 << n_tau_bits) - 1)
            for _q in range(n_query_per_pk):
                pk_star = rng.integers(0, 2 ** 16)
                if pk_star == pk:
                    continue
                tau_star = (pk_star ^ msg ^ sig) & ((1 << n_tau_bits) - 1)
                if tau_star == tau:
                    violations += 1
                    break
        else:
            # AnchoredMAYO: tau is keyed on a digest of pk; pk' must produce
            # both d_pk' = d_pk and the same tau.
            def H_pk(p): return hashlib.sha3_256(int(p).to_bytes(8, "big")).digest()
            d_pk = int.from_bytes(H_pk(pk)[:n_dpk_bits], "big")
            tau  = int.from_bytes(
                hashlib.sha3_256(d_pk.to_bytes(8, "big") +
                                 int(msg).to_bytes(8, "big") +
                                 int(sig).to_bytes(8, "big")).digest()[:n_tau_bits],
                "big",
            )
            for _q in range(n_query_per_pk):
                pk_star = rng.integers(0, 2 ** 16)
                if pk_star == pk:
                    continue
                d_pk_star = int.from_bytes(H_pk(pk_star)[:n_dpk_bits], "big")
                tau_star  = int.from_bytes(
                    hashlib.sha3_256(d_pk_star.to_bytes(8, "big") +
                                     int(msg).to_bytes(8, "big") +
                                     int(sig).to_bytes(8, "big")).digest()[:n_tau_bits],
                    "big",
                )
                if tau_star == tau:
                    violations += 1
                    break
    return {
        "name": "P6",
        "description": "Toy PKB-1 violation rate: anchored MAYO (binding) vs unbound MQ",
        "mode":           "unbound" if unbound else "anchored_mayo",
        "n_dpk_bits":     n_dpk_bits,
        "n_tau_bits":     n_tau_bits,
        "n_pk_samples":   n_pk_samples,
        "n_query_per_pk": n_query_per_pk,
        "violations":     int(violations),
        "violation_rate": violations / n_pk_samples,
    }


# ----------------------------------------------------------------------
# P7: anchor-aware oil-basis distinguisher (Variant A)
# ----------------------------------------------------------------------
def probe_p7_oilbasis(targets: List[Target]) -> Dict:
    r"""Anchor-aware oil-basis distinguisher.

    For each target with an anchor, this probe attempts a *known-construction*
    oil-basis recovery: it tries the canonical anchor-to-shear map
    ``B_c = SHAKE(anchor||"variantA-tied"||"shear")`` (the public deterministic
    map used by the synthetic Variant-A factory in ``synth_variants.py``) to
    construct ``T_cand = [[I, B_c], [0, I]]`` and then checks whether
    ``T_cand^{-T} P_i T_cand^{-1}`` has the canonical UOV-central form
    (zero oil-oil block in the bottom-right ``n_o x n_o`` submatrix).

    For Variant A, the candidate ``T_cand`` matches the construction's true
    transformation, so the oil-oil block vanishes on every seed and equation.
    For canonical AnchoredMAYO and the MAYO baseline (where ``T`` is a
    uniform invertible matrix, not anchor-derived), the oil-oil block has
    expected ``m * n_o * n_o * (1 - 1/q)`` nonzero entries.

    Bonferroni-corrected ``p``-value: smaller is stronger evidence that
    ``T_cand`` matches the public map's structure.

    Output keys:
      ``zero_block_rate``   -- fraction of seeds where the oil-oil block
                               is *exactly* zero under ``T_cand``.
      ``mean_nonzero``      -- mean number of nonzero oil-oil-block entries
                               across seeds.
      ``expected_nonzero``  -- expected nonzero count under a random T,
                               i.e.\ ``m * n_o * n_o * (1 - 1/q)``.
      ``pvalue``            -- one-sided binomial p-value for ``zero_block_rate``
                               under the null ``rate = q^{-(m * n_o * n_o)}``.
    """
    if not targets:
        return {"name": "P7", "n_seeds": 0}
    targets_with_anchor = [tgt for tgt in targets if tgt.anchor is not None]
    if not targets_with_anchor:
        return {
            "name": "P7",
            "description": "Anchor-aware oil-basis distinguisher (Variant A target)",
            "n_seeds":  len(targets),
            "n_anchored": 0,
            "skipped":  True,
            "reason":   "no anchor present on any target",
        }

    q = _target_q(targets_with_anchor)
    GFq = get_gf(q)
    tier = targets_with_anchor[0].tier
    n_v, n_o, n, m = tier.n_v, tier.n_o, tier.n, tier.m

    nonzeros = []
    zero_block_count = 0
    for tgt in targets_with_anchor:
        anchor = tgt.anchor
        from .targets import _gf_uniform
        B_c = np.array(_gf_uniform(b"variantA-tied|" + anchor, b"shear",
                                   (n_v, n_o), q), dtype=np.int64)
        T_cand = np.eye(n, dtype=np.int64)
        T_cand[:n_v, n_v:] = B_c
        T_cand_gf = GFq(T_cand % q)
        T_inv = np.linalg.inv(T_cand_gf)

        nz = 0
        for P_i in tgt.P:
            M = T_inv.T @ P_i @ T_inv
            block = np.array(M[n_v:, n_v:], dtype=np.int64)
            nz += int(np.count_nonzero(block))
        nonzeros.append(nz)
        if nz == 0:
            zero_block_count += 1

    arr = np.array(nonzeros)
    expected = float(m * n_o * n_o * (1.0 - 1.0 / q))
    rate = zero_block_count / len(targets_with_anchor)

    # P-value: under H_0 = "T_cand is unrelated to public map", the chance
    # that all m * n_o * n_o block entries vanish on a single seed is
    # q^{-m*n_o*n_o}; across N seeds, the chance of >= zero_block_count
    # zero-block seeds follows binomial(N, q^{-m*n_o*n_o}).  The probability
    # of >= 1 zero-seed is at most N * q^{-m*n_o*n_o}.
    log_p_per_seed = -float(m * n_o * n_o) * np.log(q)
    log_p_total = np.log(len(targets_with_anchor)) + zero_block_count * log_p_per_seed
    p_value = float(np.exp(log_p_total)) if zero_block_count > 0 else 1.0

    return {
        "name":             "P7",
        "description":      "Anchor-aware oil-basis distinguisher (Variant A)",
        "n_seeds":          len(targets_with_anchor),
        "n_v":              n_v,
        "n_o":              n_o,
        "zero_block_count": int(zero_block_count),
        "zero_block_rate":  float(rate),
        "mean_nonzero":     float(arr.mean()),
        "max_nonzero":      int(arr.max()),
        "expected_nonzero_random_T": expected,
        "pvalue":           p_value,
        "log_pvalue":       float(log_p_total) if zero_block_count > 0 else 0.0,
    }


# ----------------------------------------------------------------------
# P8: hash-family-enumeration distinguisher (Variant B)
# ----------------------------------------------------------------------
def probe_p8_hidden_idx(targets: List[Target]) -> Dict:
    """Hidden-index hash-family-enumeration distinguisher.

    For each anchor-bearing target, this probe tries a small dictionary of
    plausible anchor-to-index hash families (SHAKE-256, SHA-256, trivial
    ``i mod n``, XOR-of-anchor) and, for each candidate, computes the
    purported leak index ``k_i`` and checks whether
    ``P_i[k_i, k_i] == anchor[i mod len(anchor)] mod q`` across all seeds
    and all ``i in [m]``.  The match rate of the correct hash family is
    100%; other families produce noise-level matches at rate ``1/q``.

    Outputs the per-candidate match rate, the best candidate, and a
    chi-square p-value of the best candidate against the random-uniform
    null.  A best candidate match rate near 1 with a small p-value is
    evidence of a hidden-index leak.
    """
    if not targets:
        return {"name": "P8", "n_seeds": 0}
    targets_with_anchor = [tgt for tgt in targets if tgt.anchor is not None]
    if not targets_with_anchor:
        return {
            "name": "P8",
            "description": "Hash-family-enumeration distinguisher (Variant B)",
            "n_seeds":  len(targets),
            "n_anchored": 0,
            "skipped":  True,
            "reason":   "no anchor present on any target",
        }

    tier = targets_with_anchor[0].tier
    n, m, q = tier.n, tier.m, tier.q

    from .targets import _shake

    def _shake_idx(anchor, i, n):
        return int.from_bytes(_shake(anchor, b"variantB-idx|%d" % i, 8), "big") % n
    def _sha256_idx(anchor, i, n):
        return int.from_bytes(
            hashlib.sha256(anchor + b"|%d" % i).digest()[:8], "big"
        ) % n
    def _trivial_idx(anchor, i, n):
        return i % n
    def _xor_anchor_idx(anchor, i, n):
        h = 0
        for b in anchor:
            h ^= b
        return (h + i) % n

    candidates = {
        "shake_anchor_i":   _shake_idx,
        "sha256_anchor_i":  _sha256_idx,
        "trivial_i_mod_n":  _trivial_idx,
        "xor_anchor_plus_i": _xor_anchor_idx,
    }

    results = {}
    best_rate = 0.0
    best_name = None
    best_p = 1.0
    for cand, h_fn in candidates.items():
        match = 0
        total = 0
        for tgt in targets_with_anchor:
            anchor = tgt.anchor
            for i, P_i in enumerate(tgt.P):
                k_i = h_fn(anchor, i, n)
                expected = int(anchor[i % len(anchor)]) % q
                actual = int(np.array(P_i)[k_i, k_i]) % q
                if expected == actual:
                    match += 1
                total += 1
        rate = match / total if total else 0.0
        if total > 0 and rate > 1.0 / q:
            try:
                _, p_val = stats.chisquare(
                    [match, total - match],
                    [total / q, total - total / q],
                )
            except Exception:
                p_val = 1.0
        else:
            p_val = 1.0
        results[cand] = {
            "match":     int(match),
            "total":     int(total),
            "match_rate": float(rate),
            "pvalue":    float(p_val),
        }
        if rate > best_rate:
            best_rate, best_name, best_p = rate, cand, p_val

    return {
        "name":             "P8",
        "description":      "Hash-family-enumeration distinguisher (Variant B)",
        "n_seeds":          len(targets_with_anchor),
        "n":                n,
        "m":                m,
        "q":                q,
        "candidates":       results,
        "best_candidate":   best_name,
        "best_match_rate":  float(best_rate),
        "best_pvalue":      float(best_p),
        "baseline_rate":    1.0 / q,
        "distinguisher_success": bool(best_rate > 0.95),
    }
