"""Less-blatant synthetic algebraic-anchor variants for the AnchoredMAYO audit.

The legacy ``synthetic_alg_anchor`` factory in ``targets.py`` injects the
anchor's i-th byte into ``P_i[0,0]``: a textbook coefficient-level leak that
the chi-square anchor-correlation probe in P5 catches trivially.  That
factory is retained as a unit test for the audit framework (the framework
*must* fail it).

This module provides three more nuanced variants, each modelling a
different way that a Class-C algebraic anchor might accidentally introduce
structural leakage:

* **Variant A -- geometric oil-basis**.  The anchor parameterises a
  vinegar-to-oil shear matrix ``B in GF(q)^{n_v x n_o}``; the public-key
  basis change is ``T = [[I_v, B], [0, I_o]]``.  The oil subspace in
  canonical coordinates is sheared by ``B``.  None of the **coefficients**
  of ``P_i`` involving canonical index 0 depend on the anchor (because
  ``T[0,0] = 1`` and column 0 of ``T`` is the unit vector), so the
  legacy P5 anchor-correlation probe misses this leak.  Detection requires
  a *geometric* probe such as the wedge-product / oil-space-recovery probe
  (P3).

* **Variant B -- coefficient-visible diagonal at hidden index**.  The
  anchor's i-th byte is written to ``P_i[k, k]`` where ``k = HASH(anchor) mod n``.
  P5's anchor-correlation probe is **pre-registered** to inspect ``P_0[0,0]``,
  which it sees as uniform; an analyst who *knew* to check ``P_i[k_i, k_i]``
  could catch it.  This variant tests whether the audit's pre-registration
  is too narrow.

* **Variant C -- rank-r symmetric perturbation**.  The anchor seeds ``r``
  vectors ``u_1, ..., u_r in GF(q)^n`` and ``r`` scalars
  ``lambda_1, ..., lambda_r``.  Every ``F_i`` is modified to
  ``F_i + sum_j lambda_j u_j u_j^T``; the public-map matrix becomes
  ``P_i = T^T F_i T + T^T (sum_j lambda_j u_j u_j^T) T``.
  The added perturbation has rank exactly ``r``, contributing a rank-``r``
  shift uniform across all ``P_i``.  Detection signals: (i) all linear
  combinations of ``P_i`` carry the same rank-``r`` shift, so the
  MinRank-style P2 probe should see a small ``min_rank`` bias; and
  (ii) the wedge-product probe (P3) should pick up the shared low-rank
  perturbation across pairs.  Parameter ``r`` controls the leak intensity.

Together with the legacy variant these four targets give the audit
framework a falsification ladder: trivial (legacy) -> hidden index
(Variant B) -> geometric (Variant A) -> low-rank shared (Variant C).
"""

from __future__ import annotations

import hashlib
from typing import Optional

import galois
import numpy as np

from .targets import (
    GF, K_ANCHOR, M_EQNS, N_OIL, N_VARS, N_VINEGAR, Q_FIELD, Target, TierParams,
    TIER_TOY, _build_central_uov, _gf_uniform, _isomorphism_matrix,
    _pack_anchor_bytes, _public_matrices, _shake, get_gf,
)


# ----------------------------------------------------------------------
# Variant A: geometric oil-basis leak
# ----------------------------------------------------------------------
def make_synth_variant_a_oilbasis(seed_pkmap: bytes,
                                  tier: TierParams = TIER_TOY) -> Target:
    """Variant A: anchor parameterises a vinegar-to-oil shear matrix.

    ``T = [[I_{n_v}, B(anchor)], [0, I_{n_o}]]`` where ``B`` is derived from
    the anchor.  The shear preserves the UOV oil-oil-zero invariant and
    leaves ``P_i[0, 0] = F_i[0, 0]`` untouched, so the legacy P5
    anchor-correlation probe (which inspects ``P_0[0, 0]`` versus
    ``anchor[0]``) sees no signal.  The leak is purely geometric: knowing
    the anchor reveals the oil subspace.
    """
    n_v, n_o, n, q = tier.n_v, tier.n_o, tier.n, tier.q
    GFq = get_gf(q)

    F = _build_central_uov(seed_pkmap, tier)

    anchor_vec = _gf_uniform(seed_pkmap, b"variantA-anchor", (tier.k_anchor,), q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)

    # Anchor-derived shear matrix
    B = _gf_uniform(b"variantA-tied|" + anchor_bytes, b"shear", (n_v, n_o), q)

    T = np.eye(n, dtype=np.int64)
    T[:n_v, n_v:] = np.array(B, dtype=np.int64)
    T = GFq(T % q)

    P = _public_matrices(F, T)
    return Target(
        name=f"synth_a_oilbasis:{tier.name}",
        P=P, anchor=anchor_bytes,
        n=n, m=tier.m, q=q, tier=tier,
    )


# ----------------------------------------------------------------------
# Variant B: coefficient-visible diagonal at hidden index
# ----------------------------------------------------------------------
def make_synth_variant_b_hidden_index(seed_pkmap: bytes,
                                      tier: TierParams = TIER_TOY) -> Target:
    """Variant B: anchor leaks into ``P_i[k_i, k_i]`` where ``k_i`` is a
    hidden function of the anchor.

    ``k_i = HASH(anchor || i) mod n``.  Each equation has its own leak
    location.  Pre-registered P5 anchor-correlation looks at ``P_0[0, 0]``
    which sees a uniform value (because ``k_0`` is rarely 0); an analyst
    who knew the construction could decode each ``k_i`` from the anchor
    and inspect the right diagonal entry.  This variant exercises the
    cost of *pre-registration*: a too-narrow probe spec misses a leak that
    a less-narrow spec would catch.
    """
    n, q = tier.n, tier.q
    GFq = get_gf(q)

    F = _build_central_uov(seed_pkmap, tier)
    T = _isomorphism_matrix(seed_pkmap, n, q)
    P = _public_matrices(F, T)

    anchor_vec = _gf_uniform(seed_pkmap, b"variantB-anchor", (tier.k_anchor,), q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)

    # Inject anchor[i] into P_i[k_i, k_i] where k_i = SHAKE(anchor||i) mod n.
    leaked = []
    for i, P_i in enumerate(P):
        k_i = int.from_bytes(
            _shake(anchor_bytes, b"variantB-idx|%d" % i, 8), "big"
        ) % n
        P_arr = np.array(P_i, dtype=np.int64)
        P_arr[k_i, k_i] = int(anchor_bytes[i % len(anchor_bytes)]) % q
        leaked.append(GFq(P_arr))
    return Target(
        name=f"synth_b_hidden_idx:{tier.name}",
        P=leaked, anchor=anchor_bytes,
        n=n, m=tier.m, q=q, tier=tier,
    )


# ----------------------------------------------------------------------
# Variant C: rank-r symmetric perturbation
# ----------------------------------------------------------------------
def make_synth_variant_c_rank_r(seed_pkmap: bytes,
                                tier: TierParams = TIER_TOY,
                                r: int = 2) -> Target:
    """Variant C: every ``F_i`` is perturbed by the *same* anchor-derived
    rank-``r`` symmetric matrix scaled by an i-dependent scalar.

    Concretely: anchor seeds ``r`` vectors ``u_1, ..., u_r`` and a single
    ``r``-vector of scalars ``mu``.  We set
    ``F_i_new = F_i + s_i * (sum_j u_j u_j^T)`` where ``s_i`` is the
    i-th coordinate of ``mu`` in ``GF(q)``.  The resulting public matrices
    share a common rank-``r`` direction across all i, which a low-rank
    distinguisher (P2 / P3 wedge) can exploit.

    This variant captures the situation where an algebraic anchor enters
    via a low-rank summand to the central map -- a natural and somewhat
    realistic anchor interaction.
    """
    if r < 1:
        raise ValueError("r must be >= 1")
    n, q, m = tier.n, tier.q, tier.m
    GFq = get_gf(q)

    F = _build_central_uov(seed_pkmap, tier)
    T = _isomorphism_matrix(seed_pkmap, n, q)

    anchor_vec = _gf_uniform(seed_pkmap, b"variantC-anchor", (tier.k_anchor,), q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)

    # Anchor-derived rank-r perturbation
    U = _gf_uniform(b"variantC-tied|" + anchor_bytes, b"u-vectors", (r, n), q)
    mu = _gf_uniform(b"variantC-tied|" + anchor_bytes, b"mu", (m,), q)

    Pert = GFq(np.zeros((n, n), dtype=np.int64))
    U_arr = np.array(U, dtype=np.int64)
    for j in range(r):
        u = U_arr[j].reshape(-1, 1)
        Pert = Pert + GFq((u @ u.T) % q)

    F_perturbed = []
    for i, F_i in enumerate(F):
        s_i = int(mu[i])
        F_i_new = F_i + GFq((s_i * np.array(Pert, dtype=np.int64)) % q)
        F_perturbed.append(F_i_new)

    P = _public_matrices(F_perturbed, T)
    return Target(
        name=f"synth_c_rank{r}:{tier.name}",
        P=P, anchor=anchor_bytes,
        n=n, m=m, q=q, tier=tier,
    )


# ----------------------------------------------------------------------
# Convenience registry
# ----------------------------------------------------------------------
SYNTH_VARIANT_FACTORIES = {
    "synth_a_oilbasis":   make_synth_variant_a_oilbasis,
    "synth_b_hidden_idx": make_synth_variant_b_hidden_index,
    "synth_c_rank1":      lambda s, t=TIER_TOY: make_synth_variant_c_rank_r(s, t, r=1),
    "synth_c_rank2":      lambda s, t=TIER_TOY: make_synth_variant_c_rank_r(s, t, r=2),
    "synth_c_rank4":      lambda s, t=TIER_TOY: make_synth_variant_c_rank_r(s, t, r=4),
}
