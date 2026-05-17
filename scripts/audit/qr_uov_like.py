"""QR-UOV-shaped target factories for cross-family audit validation.

QR-UOV (Furue-Ikematsu-Hoshino-Takagi 2022) builds its central UOV map over
the **quotient ring** ``L = F_q[y] / g(y)`` for a public, fixed irreducible
``g(y)`` of degree ``d_g``.  Public-map coefficients live in ``L`` and are
expanded back to ``F_q`` via the companion-matrix representation of ``y``.

Anchor candidate (Class-C in our taxonomy)
------------------------------------------

``g(y)`` is **public** and **algebraically consumed** by every multiplication
in the central map -- exactly the failure mode our taxonomy isolates.  We
expose its coefficients as the audit ``anchor`` byte string, so that probes
P1 (Macaulay rank), P3 (structural fingerprint vs anchor) and P5 (anchor
correlation) can test whether the modulus *as it varies across the seed
schedule* statistically couples to the public-map coefficients.

For real QR-UOV ``g(y)`` is fixed per parameter set; we use a *family-of-
schemes* audit hypothesis -- "if a deployment re-derived ``g(y)`` from a
key seed, would the modulus leak into the public map?" -- and seed-schedule
``g(y)`` accordingly.

Tier sizes mirror QR-UOV's L1 parameter set in **structural shape only**
(d_g = 4 over q = 31), not in byte-faithful field choice; the audit
documents this approximation in paper §7.5 alongside the SNOVA-shape
caveat.

Three factories
---------------

* ``qruov_baseline`` -- canonical QR-UOV-shape, ``g(y)`` sampled
  deterministically from ``seed_pkmap`` and exposed as anchor.
* ``qruov_synth_sparse_g`` -- synthetic Class-A variant: ``g(y)`` chosen
  with low Hamming weight (forced two non-leading non-zero coefficients).
  Mimics the "weak modulus" structural regime probed by Lin--Wang (2024).
* ``qruov_synth_pinned_g`` -- synthetic Class-C *unit test*: one
  coefficient byte of ``g(y)`` is pinned into ``P_i[0, 0]``.  Used to
  verify the audit framework flags blatant modulus leakage on this family.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import List, Optional, Tuple

import galois
import numpy as np

from .targets import (
    Target, _gf_uniform, _pack_anchor_bytes, _shake, get_gf,
)


# ----------------------------------------------------------------------
# QR-UOV-like tier configuration
# ----------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class QrUovTier:
    """QR-UOV-shape audit tier.

    Dimensions are counted *in L*: ``nL_v`` vinegar coordinates over ``L``
    + ``nL_o`` oil coordinates over ``L``; ``m_L`` equations in ``L``.
    The *expanded* sizes (used by our probes) are obtained by multiplying
    each count by ``d_g`` (the degree of the modulus ``g(y)``):

        n_expanded = d_g * (nL_v + nL_o)
        m_expanded = d_g * m_L                          (one F_q-equation
                                                         per L-coefficient
                                                         of an L-equation)

    Defaults:

    * ``qruov_toy``: d_g=2, nL_v=4, nL_o=2 -> n=12, m=8
    * ``qruov_l1``:  d_g=4, nL_v=14, nL_o=2 -> n=64, m=32  (shape-match
      QR-UOV-(v=56,o=8) at L1, in our q=31 audit field)
    """
    name: str
    q: int
    d_g: int
    nL_v: int
    nL_o: int
    m_L: int

    @property
    def n(self) -> int:
        return self.d_g * (self.nL_v + self.nL_o)

    @property
    def n_v(self) -> int:
        return self.d_g * self.nL_v

    @property
    def n_o(self) -> int:
        return self.d_g * self.nL_o

    @property
    def m(self) -> int:
        return self.d_g * self.m_L

    @property
    def k_anchor(self) -> int:
        # anchor = g(y) coefficients of length d_g (the leading coefficient
        # is fixed at 1 for a monic modulus; we include it for transparency).
        return self.d_g + 1


QRUOV_TIER_TOY = QrUovTier(
    name="qruov-toy",
    q=31,
    d_g=2,
    nL_v=4,
    nL_o=2,
    m_L=4,
)

QRUOV_TIER_L1 = QrUovTier(
    name="qruov-l1-shaped",
    q=31,
    d_g=4,
    nL_v=14,
    nL_o=2,
    m_L=8,
)


# QR-UOV-Ipks-1 NIST L1 official parameters:
#   q=127, v=156, m=54, L=3 (so d_g=3, nL_v=v/L=52, nL_o=m_L=m/L=18).
# Derived: n = d_g*(nL_v+nL_o) = 210, m = d_g*m_L = 54.
# The modulus g(y) is re-derived per seed (family-of-schemes convention);
# the byte-faithful upstream reference fixes g(y)=x^3-x-1, but the
# PKB-1 attack of paper Theorem 3.4 is independent of g.
QRUOV_TIER_IPKS1 = QrUovTier(
    name="qruov-ipks1",
    q=127,
    d_g=3,
    nL_v=52,
    nL_o=18,
    m_L=18,
)


# ----------------------------------------------------------------------
# Modulus polynomial sampling
# ----------------------------------------------------------------------
def _sample_irreducible_g(seed: bytes, tag: bytes,
                          d_g: int, q: int) -> galois.Poly:
    """Sample a monic irreducible polynomial of degree ``d_g`` over GF(q),
    deterministically from ``seed`` + ``tag``.

    Strategy: enumerate candidate constant-term + middle-coefficient bytes
    derived from a SHAKE stream until we hit an irreducible polynomial.
    For (d_g, q) = (4, 31) the irreducibility density is roughly 1/4 so
    enumeration terminates in O(8) tries on average.
    """
    GFq = get_gf(q)
    counter = 0
    while True:
        raw = _shake(seed, tag + b"|g|%d" % counter, 16 * d_g)
        coeffs = np.frombuffer(raw[:d_g], dtype=np.uint8).astype(np.int64) % q
        # Monic leading coefficient.
        full = np.concatenate([[1], coeffs])
        poly = galois.Poly(GFq(full))
        if poly.is_irreducible():
            return poly
        counter += 1
        if counter > 256:
            raise RuntimeError(
                f"could not find irreducible degree-{d_g} polynomial over GF({q})"
            )


def _sample_sparse_g(seed: bytes, tag: bytes,
                     d_g: int, q: int) -> galois.Poly:
    """Sample a monic *low-Hamming-weight* polynomial of degree ``d_g``:
    only the constant term and one middle term are non-zero, both derived
    from the seed.  Used by the Class-A "weak modulus" synthetic variant
    to stress-test whether sparsity in ``g(y)`` correlates with detectable
    rank/structural anomalies in the expanded public map.

    Note: this polynomial is **not required** to be irreducible -- the
    point of the synthetic variant is precisely to probe a structurally
    weak modulus regime.  We do require ``g(0) != 0`` (non-zero constant
    term) so the companion-matrix representation of ``y`` remains
    invertible.
    """
    GFq = get_gf(q)
    raw = _shake(seed, tag + b"|sparseg", 16)
    c0 = (int(raw[0]) % (q - 1)) + 1  # constant term in [1, q-1]
    mid_idx = 1 + (int(raw[1]) % (d_g - 1))  # 1 <= mid_idx <= d_g - 1
    c_mid = (int(raw[2]) % (q - 1)) + 1
    coeffs = np.zeros(d_g + 1, dtype=np.int64)
    coeffs[0] = 1
    coeffs[d_g - mid_idx] = c_mid
    coeffs[d_g] = c0
    return galois.Poly(GFq(coeffs))


# ----------------------------------------------------------------------
# Companion-matrix expansion of L = F_q[y] / g(y)
# ----------------------------------------------------------------------
def _companion_matrix(g: galois.Poly) -> np.ndarray:
    """Companion matrix ``M_y`` of multiplication-by-``y`` on L, in the
    standard ``{1, y, y^2, ..., y^{d_g-1}}`` basis.

    For ``g(y) = y^d + g_{d-1} y^{d-1} + ... + g_0``, ``M_y`` is the
    ``d x d`` matrix with sub-diagonal of 1s and last column
    ``[-g_0, -g_1, ..., -g_{d-1}]``.
    """
    d = g.degree
    q = g.field.order
    # galois Poly stores coefficients in descending order: coeffs[0] = leading.
    coeffs = np.array(g.coeffs, dtype=np.int64)  # length d+1, coeffs[0] = 1
    # g_i for i = 0..d-1: g(y) = y^d + sum_{i=0}^{d-1} g_i y^i
    # coeffs in descending order means coeffs[1] = g_{d-1}, ..., coeffs[d] = g_0
    g_i = coeffs[1:][::-1]  # g_i[0] = g_0, g_i[1] = g_1, ...

    M = np.zeros((d, d), dtype=np.int64)
    # Sub-diagonal: shift-by-y on basis vectors 1, y, ..., y^{d-2}
    for i in range(d - 1):
        M[i + 1, i] = 1
    # Last column: y * y^{d-1} = y^d = -sum_i g_i y^i (in L)
    for i in range(d):
        M[i, d - 1] = (-int(g_i[i])) % q
    return M


def _l_multiply_matrix(a_l: np.ndarray, M_y: np.ndarray, q: int) -> np.ndarray:
    """For ``a in L = F_q[y]/g(y)`` given by its coefficient vector ``a_l``
    of length ``d``, return the ``d x d`` matrix ``M_a`` representing
    multiplication-by-``a`` in the basis ``{1, y, ..., y^{d-1}}``.

    Concretely: ``M_a = sum_{k=0}^{d-1} a_l[k] * M_y^k``.
    """
    d = M_y.shape[0]
    M_a = np.zeros((d, d), dtype=np.int64)
    M_y_pow = np.eye(d, dtype=np.int64) % q
    for k in range(d):
        M_a = (M_a + int(a_l[k]) * M_y_pow) % q
        if k + 1 < d:
            M_y_pow = (M_y_pow @ M_y) % q
    return M_a


# ----------------------------------------------------------------------
# Central QR-UOV map over L
# ----------------------------------------------------------------------
def _build_central_map_over_L(seed: bytes, tier: QrUovTier
                              ) -> List[np.ndarray]:
    """Build the ``m_L`` central UOV matrices ``F_iL`` of size
    ``(nL_v + nL_o) x (nL_v + nL_o)`` over ``L``.

    Each entry ``F_iL[a, b]`` is a length-``d_g`` coefficient vector
    representing an element of ``L = F_q[y]/g(y)``.  We keep the same
    UOV invariant: vinegar-vinegar block is symmetric (in ``L``);
    vinegar-oil block is arbitrary (in ``L``); oil-oil block is zero.
    """
    nL_v, nL_o, m_L, d_g, q = (
        tier.nL_v, tier.nL_o, tier.m_L, tier.d_g, tier.q,
    )
    nL = nL_v + nL_o
    mats = []
    for i in range(m_L):
        F_iL = np.zeros((nL, nL, d_g), dtype=np.int64)
        # vinegar-vinegar (symmetric in L)
        for r in range(nL_v):
            for c in range(r, nL_v):
                raw = _shake(seed, b"qruov-vv|%d|%d|%d" % (i, r, c),
                             d_g + 4)
                elem = np.frombuffer(raw[:d_g], dtype=np.uint8).astype(np.int64) % q
                F_iL[r, c] = elem
                F_iL[c, r] = elem
        # vinegar-oil
        for r in range(nL_v):
            for c in range(nL_o):
                raw = _shake(seed, b"qruov-vo|%d|%d|%d" % (i, r, c),
                             d_g + 4)
                elem = np.frombuffer(raw[:d_g], dtype=np.uint8).astype(np.int64) % q
                F_iL[r, nL_v + c] = elem
                F_iL[nL_v + c, r] = elem
        # oil-oil block stays zero
        mats.append(F_iL)
    return mats


def _expand_to_Fq_equations(F_iL_list: List[np.ndarray], M_y: np.ndarray,
                            tier: QrUovTier) -> List[np.ndarray]:
    """Convert ``m_L`` ``L``-valued central matrices to ``m_L * d_g``
    symmetric ``F_q``-matrices.

    Math.  Each ``L``-equation has the form
        F^L_i(x_L) = x_L^T F_iL x_L  in  L,
    where ``x_L in L^{nL}``.  Expanding ``x_r = sum_a x_r^{(a)} y^a``,
        F^L_i(x_L) = sum_{r, c, a, b} F_iL[r, c] * x_r^{(a)} x_c^{(b)} * y^{a+b}.
    The coefficient of ``y^k`` in ``F_iL[r, c] * y^{a+b} mod g(y)`` equals
    ``(M_y^{a+b} @ F_iL[r, c])[k]`` (acting on the coefficient column
    vector).  So each ``L``-equation contributes ``d_g`` ``F_q``-equations
        F^{(k)}_i[r*d_g + a, c*d_g + b] = sum_j M_y^{a+b}[k, j] * F_iL[r, c, j].

    The resulting ``F^{(k)}_i`` is automatically symmetric because
    ``F_iL[r, c] = F_iL[c, r]`` (symmetry of the central form in ``L``)
    and the formula above is symmetric under (r, a) <-> (c, b).

    Vectorised via a single einsum per ``L``-equation; output length
    is ``m_L * d_g = tier.m``.
    """
    d = tier.d_g
    q = tier.q
    nL = F_iL_list[0].shape[0]
    n = nL * d

    M_y_pows = [np.eye(d, dtype=np.int64) % q]
    for _ in range(2 * d - 1):
        M_y_pows.append((M_y_pows[-1] @ M_y) % q)
    # M_tensor[a, b] = M_y^{a+b}, shape (d, d, d, d).
    M_tensor = np.zeros((d, d, d, d), dtype=np.int64)
    for a in range(d):
        for b in range(d):
            M_tensor[a, b] = M_y_pows[a + b] % q

    out = []
    for F_iL in F_iL_list:
        # Result tensor: F_out[k, r, a, c, b] = sum_j M_tensor[a, b, k, j] * F_iL[r, c, j]
        F_out = np.einsum('abkj,rcj->kracb', M_tensor, F_iL) % q
        # Flatten (r, a) and (c, b) axes -> (d, n, n) -> d output matrices.
        F_flat = F_out.reshape(d, n, n)
        for k in range(d):
            out.append(F_flat[k].copy())
    return out


def _isomorphism_matrix(seed: bytes, n: int, q: int) -> np.ndarray:
    """Sample an invertible n x n matrix over F_q deterministically from seed."""
    GFq = get_gf(q)
    counter = 0
    while True:
        raw = _shake(seed, b"qruov-T|%d" % counter, n * n + 16)
        arr = np.frombuffer(raw[: n * n], dtype=np.uint8).astype(np.int64) % q
        T = arr.reshape((n, n))
        try:
            np.linalg.inv(GFq(T))
            return T
        except np.linalg.LinAlgError:
            counter += 1


def _public_matrices(F_list: List[np.ndarray], T: np.ndarray, q: int
                     ) -> List[np.ndarray]:
    Tt = T.T % q
    return [((Tt @ F) % q @ T) % q for F in F_list]


def _pack_g_anchor(g: galois.Poly, d_g: int) -> bytes:
    """Pack g(y)'s coefficients (including leading 1) into a byte string.
    Coefficients stored in ascending order of degree: byte 0 = constant
    term, byte 1 = y-coefficient, ..., byte d_g = leading (always 1)."""
    coeffs = np.array(g.coeffs, dtype=np.int64)[::-1]  # ascending order
    if len(coeffs) < d_g + 1:
        # pad if galois trimmed leading zeros (shouldn't happen for monic g)
        coeffs = np.concatenate([coeffs, np.zeros(d_g + 1 - len(coeffs))])
    return bytes(int(c) % 256 for c in coeffs[: d_g + 1])


# ----------------------------------------------------------------------
# Factories
# ----------------------------------------------------------------------
def make_qruov_baseline(seed_pkmap: bytes,
                        tier: QrUovTier = QRUOV_TIER_TOY) -> Target:
    """Canonical QR-UOV shape: irreducible ``g(y)`` sampled from seed,
    exposed as anchor; public map P = T^T F T with random invertible T.
    """
    g = _sample_irreducible_g(seed_pkmap, b"baseline", tier.d_g, tier.q)
    M_y = _companion_matrix(g)
    F_L = _build_central_map_over_L(seed_pkmap, tier)
    F_expanded = _expand_to_Fq_equations(F_L, M_y, tier)
    T = _isomorphism_matrix(seed_pkmap, tier.n, tier.q)
    P = _public_matrices(F_expanded, T, tier.q)

    GFq = get_gf(tier.q)
    anchor = _pack_g_anchor(g, tier.d_g)
    return Target(
        name=f"qruov_baseline:{tier.name}",
        P=[GFq(p) for p in P], anchor=anchor,
        n=tier.n, m=tier.m, q=tier.q, tier=None,
    )


def make_qruov_synth_sparse_g(seed_pkmap: bytes,
                              tier: QrUovTier = QRUOV_TIER_TOY) -> Target:
    """Synthetic Class-A: ``g(y)`` is forced to low Hamming weight (two
    non-leading non-zero coefficients).  This is a deliberately *weak
    modulus* regime that stresses the audit framework's sensitivity to
    structural sparsity in ``L``.

    Not guaranteed to be irreducible (the spec would reject this g, but
    the audit specifically probes the consequence of an adversary-friendly
    modulus -- the framework should pick up the resulting structural
    distinguisher).
    """
    g = _sample_sparse_g(seed_pkmap, b"sparse", tier.d_g, tier.q)
    M_y = _companion_matrix(g)
    F_L = _build_central_map_over_L(seed_pkmap, tier)
    F_expanded = _expand_to_Fq_equations(F_L, M_y, tier)
    T = _isomorphism_matrix(seed_pkmap, tier.n, tier.q)
    P = _public_matrices(F_expanded, T, tier.q)

    GFq = get_gf(tier.q)
    anchor = _pack_g_anchor(g, tier.d_g)
    return Target(
        name=f"qruov_synth_sparse_g:{tier.name}",
        P=[GFq(p) for p in P], anchor=anchor,
        n=tier.n, m=tier.m, q=tier.q, tier=None,
    )


def make_qruov_synth_pinned_g(seed_pkmap: bytes,
                              tier: QrUovTier = QRUOV_TIER_TOY) -> Target:
    """Synthetic Class-C *unit test*: irreducible ``g(y)`` as baseline,
    but the constant term of ``g(y)`` is *pinned* into ``P_i[0, 0]`` for
    every public matrix.  Blatantly violates the no-leak invariant;
    serves as the audit framework's sanity check on the QR-UOV family.
    """
    g = _sample_irreducible_g(seed_pkmap, b"pinned", tier.d_g, tier.q)
    M_y = _companion_matrix(g)
    F_L = _build_central_map_over_L(seed_pkmap, tier)
    F_expanded = _expand_to_Fq_equations(F_L, M_y, tier)
    T = _isomorphism_matrix(seed_pkmap, tier.n, tier.q)
    P = _public_matrices(F_expanded, T, tier.q)

    GFq = get_gf(tier.q)
    anchor = _pack_g_anchor(g, tier.d_g)
    g0 = int(anchor[0]) % tier.q  # constant coefficient
    leaked = []
    for P_i in P:
        arr = P_i.copy()
        arr[0, 0] = g0
        leaked.append(GFq(arr % tier.q))
    return Target(
        name=f"qruov_synth_pinned_g:{tier.name}",
        P=leaked, anchor=anchor,
        n=tier.n, m=tier.m, q=tier.q, tier=None,
    )


QRUOV_LIKE_FACTORIES = {
    "qruov_baseline":         make_qruov_baseline,
    "qruov_synth_sparse_g":   make_qruov_synth_sparse_g,
    "qruov_synth_pinned_g":   make_qruov_synth_pinned_g,
}
