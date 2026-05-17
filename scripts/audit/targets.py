"""Target factories for the AnchoredMAYO audit (Fast / L1-shaped tiers).

Each factory returns, for a given 32-byte ``seed_pkmap`` and an optional
``TierParams`` configuration, the symmetric coefficient matrices
``[M_1, ..., M_m]`` of an MQ system

    P_i(x) = x^T M_i x      (over F_q, q = tier.q)

together with optional anchor data ``c`` (uniform F_q^k_anchor).

Tiers
-----

* ``TIER_TOY``  -- ``(q=31, n=12, n_v=8, n_o=4, m=4)``.  Used by the original
  Fast-tier audit so probes finish in seconds.  This is the default tier for
  backwards compatibility.
* ``TIER_L1``   -- ``(q=31, n=66, n_v=58, n_o=8, m=64)``.  These are MAYO L1's
  dimensions kept over an odd-prime field so the probes' symmetric-matrix
  algebra remains valid.  We deliberately retain ``q=31`` instead of MAYO's
  ``q=16``: the char-2 cancellation issue documented below means that a
  symmetric-matrix audit framework would otherwise have to be rewritten in
  the upper-triangular polar-form convention.  Since the probes look for
  *structural* distinguishers (rank deficits, oil-space coincidences,
  anchor--coefficient correlations), the dimension regime is what matters,
  not the byte-faithful field choice.  We document this as an explicit
  audit-tier limitation in paper §7.5.

The construction of the *public* map mirrors UOV/MAYO at the chosen size:

    F_i(x)  =   <x_v, A_i x_v>      (vinegar-vinegar, full quadratic)
              + <x_v, B_i x_o>      (mixed, linear in oil)
              + (oil-oil block is **zero** by UOV invariant)
    P_i(x)  = F_i(T x)              with T linear and invertible

Synthetic algebraic-anchor variants are kept separate (see
``synth_variants.py``); this module is responsible for the canonical
``mayo_baseline`` and ``anchored_mayo`` factories plus the *legacy*
``synthetic_alg_anchor`` that injects anchor bytes into ``P_i[0,0]``
(retained as a sanity test for the audit framework).

All randomness is seeded by SHAKE-256 / SHA3-256 to make the probes
reproducible.  Each factory returns a ``Target`` object so the probes can
poll the public-map matrices and the (optional) anchor without knowing the
internal construction.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Dict, List, Optional

import galois
import numpy as np

# ----------------------------------------------------------------------
# Tier configuration
# ----------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class TierParams:
    """Audit tier parameters.

    For ``q != 2^k`` (odd-prime field) the probes use the symmetric-matrix
    convention.  Char-2 fields would require the upper-triangular polar-form
    convention; the audit framework currently keeps to odd-prime fields and
    documents this in §7.5.
    """
    name: str
    q: int
    n: int
    n_v: int
    n_o: int
    m: int
    k_anchor: int

    def __post_init__(self) -> None:
        if self.n_v + self.n_o != self.n:
            raise ValueError("n_v + n_o must equal n")


TIER_TOY = TierParams(
    name="toy",
    q=31,
    n=12,
    n_v=8,
    n_o=4,
    m=4,
    k_anchor=2,
)

TIER_L1 = TierParams(
    name="l1-shaped",
    q=31,
    n=66,
    n_v=58,
    n_o=8,
    m=64,
    k_anchor=8,
)


# Legacy module-level constants -- retained for backwards compatibility with
# scripts that import ``Q_FIELD``, ``N_VARS``, ... directly.  These reflect
# the toy tier; new code should query the active ``TierParams`` instead.
Q_FIELD: int = TIER_TOY.q
N_VARS: int = TIER_TOY.n
N_VINEGAR: int = TIER_TOY.n_v
N_OIL: int = TIER_TOY.n_o
M_EQNS: int = TIER_TOY.m
K_ANCHOR: int = TIER_TOY.k_anchor


# ----------------------------------------------------------------------
# Field cache
# ----------------------------------------------------------------------
_GF_CACHE: Dict[int, galois.FieldArray] = {}


def get_gf(q: int) -> galois.FieldArray:
    """Return ``galois.GF(q)``, cached so repeated calls are cheap."""
    if q not in _GF_CACHE:
        _GF_CACHE[q] = galois.GF(q)
    return _GF_CACHE[q]


# ``GF`` exported for the toy tier; new code should call ``get_gf(tier.q)``.
GF: galois.FieldArray = get_gf(Q_FIELD)


# ----------------------------------------------------------------------
# Determinism helpers
# ----------------------------------------------------------------------
def _shake(seed: bytes, tag: bytes, nbytes: int) -> bytes:
    h = hashlib.shake_256()
    h.update(seed + b"|" + tag)
    return h.digest(nbytes)


def _gf_from_bytes(buf: bytes, count: int, q: int) -> galois.FieldArray:
    """Map ``buf`` to ``count`` GF(q) elements (one byte per element,
    reduced mod q to remove modulo bias)."""
    if len(buf) < count:
        raise ValueError("buffer too short for requested field elements")
    arr = np.frombuffer(buf[:count], dtype=np.uint8).astype(np.int64) % q
    return get_gf(q)(arr)


def _gf_uniform(seed: bytes, tag: bytes, shape, q: int) -> galois.FieldArray:
    n = int(np.prod(shape))
    raw = _shake(seed, tag, n + 8)
    elems = _gf_from_bytes(raw, n, q)
    return elems.reshape(shape)


def _random_invertible(seed: bytes, tag: bytes, n: int, q: int) -> galois.FieldArray:
    """Sample a uniform invertible matrix in GF(q)^{n x n}."""
    counter = 0
    while True:
        T = _gf_uniform(seed, tag + b"|%d" % counter, (n, n), q)
        try:
            np.linalg.inv(T)
            return T
        except np.linalg.LinAlgError:
            counter += 1


# ----------------------------------------------------------------------
# Symmetric quadratic-form helpers
# ----------------------------------------------------------------------
def _symmetric_random(seed: bytes, tag: bytes, n: int, q: int) -> galois.FieldArray:
    """Random symmetric n x n matrix in GF(q)."""
    A = _gf_uniform(seed, tag, (n, n), q)
    upper = np.triu(np.array(A, dtype=np.int64), k=0)
    sym = upper + upper.T - np.diag(np.diag(upper))
    return get_gf(q)(sym % q)


def _build_central_uov(seed: bytes, tier: TierParams) -> List[galois.FieldArray]:
    """Build the m central UOV matrices ``F_i`` of size n x n, with the
    oil-oil block forced to zero."""
    n_v, n_o, m, q = tier.n_v, tier.n_o, tier.m, tier.q
    n = n_v + n_o
    GFq = get_gf(q)
    mats = []
    for i in range(m):
        A_vv = _symmetric_random(seed, b"uov-vv|%d" % i, n_v, q)
        B_vo = _gf_uniform(seed, b"uov-vo|%d" % i, (n_v, n_o), q)
        F = np.zeros((n, n), dtype=np.int64)
        F[:n_v, :n_v] = np.array(A_vv, dtype=np.int64)
        F[:n_v, n_v:] = np.array(B_vo, dtype=np.int64)
        F[n_v:, :n_v] = np.array(B_vo, dtype=np.int64).T
        mats.append(GFq(F))
    return mats


def _isomorphism_matrix(seed: bytes, n: int, q: int,
                        anchor: Optional[bytes] = None) -> galois.FieldArray:
    """Pick an invertible T in GF(q)^{n x n} which encodes the public/secret
    coordinate change.

    When ``anchor`` is provided we *deterministically* derive ``T`` from the
    anchor bytes -- this is the algebraic-anchor (Class-C) construction
    used by the legacy synthetic variant; new variants live in
    ``synth_variants.py``."""
    if anchor is None:
        return _random_invertible(seed, b"T", n, q)
    return _random_invertible(b"anchor-tied|" + anchor, b"T-fromc", n, q)


def _public_matrices(F_mats: List[galois.FieldArray],
                     T: galois.FieldArray) -> List[galois.FieldArray]:
    """``P_i = T^T F_i T`` for each i."""
    Tt = T.T
    return [Tt @ F @ T for F in F_mats]


def _pack_anchor_bytes(anchor: galois.FieldArray) -> bytes:
    """Pack a GF(q) anchor vector into a byte string (one byte per element).
    Non-injective when q < 256, which is fine because the audit probes use
    the byte buffer as an opaque domain-separation tag."""
    flat = np.array(anchor, dtype=np.int64).flatten()
    return bytes(int(v) % 256 for v in flat)


# ----------------------------------------------------------------------
# Target dataclass
# ----------------------------------------------------------------------
@dataclasses.dataclass
class Target:
    name: str
    P: List[galois.FieldArray]
    anchor: Optional[bytes]
    n: int
    m: int
    q: int
    tier: Optional[TierParams] = None

    def evaluate(self, x: galois.FieldArray) -> galois.FieldArray:
        """Evaluate y_i = x^T P_i x for each i."""
        out = np.zeros(self.m, dtype=np.int64)
        for i, P_i in enumerate(self.P):
            v = (x @ P_i) @ x
            out[i] = int(v)
        return get_gf(self.q)(out)


# ----------------------------------------------------------------------
# Public factories (tier-parameterised)
# ----------------------------------------------------------------------
def make_mayo_baseline(seed_pkmap: bytes,
                       tier: TierParams = TIER_TOY) -> Target:
    """Plain UOV/MAYO public map; no anchor."""
    F = _build_central_uov(seed_pkmap, tier)
    T = _isomorphism_matrix(seed_pkmap, tier.n, tier.q, anchor=None)
    P = _public_matrices(F, T)
    return Target(name=f"mayo_baseline:{tier.name}",
                  P=P, anchor=None,
                  n=tier.n, m=tier.m, q=tier.q, tier=tier)


def make_anchored_mayo(seed_pkmap: bytes,
                       tier: TierParams = TIER_TOY) -> Target:
    """AnchoredMAYO (Class B): public map identical to MAYO baseline; anchor
    data is sampled uniformly and stored alongside but never feeds the
    public-map derivation."""
    F = _build_central_uov(seed_pkmap, tier)
    T = _isomorphism_matrix(seed_pkmap, tier.n, tier.q, anchor=None)
    P = _public_matrices(F, T)

    anchor_vec = _gf_uniform(seed_pkmap, b"anchor-c", (tier.k_anchor,), tier.q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)
    return Target(name=f"anchored_mayo:{tier.name}",
                  P=P, anchor=anchor_bytes,
                  n=tier.n, m=tier.m, q=tier.q, tier=tier)


def make_synthetic_alg_anchor(seed_pkmap: bytes,
                              tier: TierParams = TIER_TOY) -> Target:
    """Class-C synthetic construction (legacy/blatant).

    Standard MAYO public map is built as in the baseline; on top of that we
    *inject* the anchor data into a public-map coefficient by overwriting
    the diagonal ``(0,0)`` entry of every ``P_i`` with the anchor's i-th
    byte (reduced mod ``q``).  This is a deliberately blatant
    algebraic-anchor leak retained as a *unit test* for the audit framework
    (the framework must catch it).  More realistic variants live in
    ``synth_variants.py``.
    """
    anchor_vec = _gf_uniform(seed_pkmap, b"anchor-c", (tier.k_anchor,), tier.q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)
    F = _build_central_uov(seed_pkmap, tier)
    T = _isomorphism_matrix(seed_pkmap, tier.n, tier.q, anchor=None)
    P = _public_matrices(F, T)

    leaked = []
    GFq = get_gf(tier.q)
    for i, P_i in enumerate(P):
        P_arr = np.array(P_i, dtype=np.int64)
        P_arr[0, 0] = int(anchor_bytes[i % len(anchor_bytes)]) % tier.q
        leaked.append(GFq(P_arr))
    return Target(name=f"synthetic_alg_anchor:{tier.name}",
                  P=leaked, anchor=anchor_bytes,
                  n=tier.n, m=tier.m, q=tier.q, tier=tier)


FACTORIES = {
    "mayo_baseline":          make_mayo_baseline,
    "anchored_mayo":          make_anchored_mayo,
    "synthetic_alg_anchor":   make_synthetic_alg_anchor,
}


def make_seed_schedule(num_seeds: int,
                       master: bytes = b"audit-fast-v1") -> List[bytes]:
    """Deterministic 32-byte seed schedule.  Part of the audit's
    pre-registered protocol: every probe is run with the same seed schedule
    and the same number of seeds for every target."""
    h = hashlib.shake_256()
    h.update(master)
    raw = h.digest(32 * num_seeds)
    return [raw[32 * i : 32 * (i + 1)] for i in range(num_seeds)]
