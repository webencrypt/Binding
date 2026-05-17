"""SNOVA-like target factories for cross-family audit validation.

SNOVA's distinguishing feature is that the public-map matrices live over a
non-commutative ring of small matrices ``R = M_r(F_q)`` rather than over a
commutative field.  A generic UOV-shaped public map ``P_i = T^T F_i T`` is
replaced by a block-ring map where every "scalar" entry is itself an
``r x r`` matrix in ``F_q``, and the ``T`` map is block-invertible.

For audit purposes we implement a deliberately simplified SNOVA-like
construction:

* the small ring is ``R = M_2(F_q)`` (2x2 matrices over ``F_q``);
* the audit dimension counts **blocks**: ``nb_v`` vinegar blocks +
  ``nb_o`` oil blocks; the **expanded** matrix size is
  ``n = 2 * (nb_v + nb_o)``;
* each ``F_i`` is a symmetric block matrix with vinegar-vinegar block,
  vinegar-oil block (linear in the oil block), and a zero oil-oil
  block at the block level;
* ``T`` is a block-diagonal invertible matrix (each diagonal block is
  an invertible 2x2 matrix in ``F_q``);
* ``P_i = T^T F_i T`` at the block level, with the result expanded back
  to a ``n x n`` matrix over ``F_q`` for use by the existing probes.

This captures SNOVA's "block-rank constrained" structural regime without
modelling the full non-commutative algebra of SNOVA's submission.  The
audit framework should be similarly able to flag/not-flag the same
classes of anchor leakage on this family as on plain UOV-shape.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Optional

import galois
import numpy as np

from .targets import (
    Target, TierParams, _gf_uniform, _pack_anchor_bytes, _shake, get_gf,
)


# ----------------------------------------------------------------------
# SNOVA-like tier configuration
# ----------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class SnovaTier:
    """SNOVA-like audit tier.

    Sizes chosen so the expanded matrix has comparable dimension to the
    AnchoredMAYO audit tier:

    * ``snova_toy``:    nb_v=4, nb_o=2, m=4   -> expanded n=12, m=4
    * ``snova_l1``:     nb_v=29, nb_o=4, m=24 -> expanded n=66, m=24
    """
    name: str
    q: int
    nb_v: int
    nb_o: int
    m: int
    block_size: int  # always 2 in this audit
    k_anchor: int

    @property
    def n_blocks(self) -> int:
        return self.nb_v + self.nb_o

    @property
    def n(self) -> int:
        return self.block_size * self.n_blocks

    @property
    def n_v(self) -> int:
        return self.block_size * self.nb_v

    @property
    def n_o(self) -> int:
        return self.block_size * self.nb_o


SNOVA_TIER_TOY = SnovaTier(
    name="snova-toy",
    q=31,
    nb_v=4,
    nb_o=2,
    m=4,
    block_size=2,
    k_anchor=2,
)

SNOVA_TIER_L1 = SnovaTier(
    name="snova-l1-shaped",
    q=31,
    nb_v=29,
    nb_o=4,
    m=24,
    block_size=2,
    k_anchor=8,
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _random_block_invertible_2x2(seed: bytes, tag: bytes, q: int) -> np.ndarray:
    """Sample an invertible 2x2 matrix in F_q^{2x2}."""
    GFq = get_gf(q)
    counter = 0
    while True:
        raw = _shake(seed, tag + b"|%d" % counter, 8)
        arr = np.frombuffer(raw[:4], dtype=np.uint8).astype(np.int64) % q
        M = arr.reshape((2, 2))
        try:
            np.linalg.inv(GFq(M))
            return M
        except np.linalg.LinAlgError:
            counter += 1


def _random_2x2(seed: bytes, tag: bytes, q: int) -> np.ndarray:
    raw = _shake(seed, tag, 8)
    arr = np.frombuffer(raw[:4], dtype=np.uint8).astype(np.int64) % q
    return arr.reshape((2, 2))


def _block_eye(n_blocks: int, block_size: int, q: int) -> np.ndarray:
    """Return identity block-matrix of n_blocks x n_blocks 2x2 blocks."""
    n = n_blocks * block_size
    return np.eye(n, dtype=np.int64) % q


def _expand_block_matrix(blocks: np.ndarray, q: int) -> np.ndarray:
    """``blocks`` has shape (nb, nb, b, b); return a (nb*b, nb*b) matrix."""
    nb = blocks.shape[0]
    b = blocks.shape[2]
    n = nb * b
    out = np.zeros((n, n), dtype=np.int64)
    for i in range(nb):
        for j in range(nb):
            out[i*b:(i+1)*b, j*b:(j+1)*b] = blocks[i, j] % q
    return out % q


def _build_snova_central(seed: bytes, tier: SnovaTier) -> list:
    """Build m central UOV-shape block matrices ``F_1, ..., F_m`` of
    expanded size ``n x n``.  Each ``F_i`` is symmetric (in the expanded
    sense) with a zero oil-oil block."""
    nb_v, nb_o, m, q, b = tier.nb_v, tier.nb_o, tier.m, tier.q, tier.block_size
    nb = nb_v + nb_o
    mats = []
    for i in range(m):
        blocks = np.zeros((nb, nb, b, b), dtype=np.int64)
        # vinegar-vinegar (symmetric in block grid; lower-tri = upper-tri.T)
        for r in range(nb_v):
            for c in range(r, nb_v):
                blk = _random_2x2(seed, b"snova-vv|%d|%d|%d" % (i, r, c), q)
                if r == c:
                    blk = (blk + blk.T) % q  # block-level symmetric on diagonal
                blocks[r, c] = blk
                blocks[c, r] = blk.T % q
        # vinegar-oil
        for r in range(nb_v):
            for c in range(nb_o):
                blk = _random_2x2(seed, b"snova-vo|%d|%d|%d" % (i, r, c), q)
                blocks[r, nb_v + c] = blk
                blocks[nb_v + c, r] = blk.T % q
        # oil-oil block stays zero by SNOVA-shape invariant
        F = _expand_block_matrix(blocks, q)
        mats.append(F)
    return mats


def _build_block_diagonal_T(seed: bytes, tier: SnovaTier) -> np.ndarray:
    """Block-diagonal T: each diagonal block is invertible 2x2 in F_q."""
    nb, b, q = tier.n_blocks, tier.block_size, tier.q
    n = nb * b
    T = np.zeros((n, n), dtype=np.int64)
    for r in range(nb):
        T[r*b:(r+1)*b, r*b:(r+1)*b] = _random_block_invertible_2x2(
            seed, b"snova-T|%d" % r, q
        )
    return T % q


def _public_block_matrices(F_list: list, T: np.ndarray, q: int) -> list:
    Tt = T.T % q
    return [(Tt @ F @ T) % q for F in F_list]


# ----------------------------------------------------------------------
# Factories
# ----------------------------------------------------------------------
def make_snova_baseline(seed_pkmap: bytes,
                        tier: SnovaTier = SNOVA_TIER_TOY) -> Target:
    """Plain SNOVA-like baseline; no anchor."""
    F = _build_snova_central(seed_pkmap, tier)
    T = _build_block_diagonal_T(seed_pkmap, tier)
    P = _public_block_matrices(F, T, tier.q)
    GFq = get_gf(tier.q)
    return Target(
        name=f"snova_baseline:{tier.name}",
        P=[GFq(p) for p in P], anchor=None,
        n=tier.n, m=tier.m, q=tier.q, tier=None,
    )


def make_snova_anchored(seed_pkmap: bytes,
                        tier: SnovaTier = SNOVA_TIER_TOY) -> Target:
    """SNOVA-like Class-B anchor: anchor data attached but unused."""
    F = _build_snova_central(seed_pkmap, tier)
    T = _build_block_diagonal_T(seed_pkmap, tier)
    P = _public_block_matrices(F, T, tier.q)
    GFq = get_gf(tier.q)

    anchor_vec = _gf_uniform(seed_pkmap, b"snova-anchor",
                             (tier.k_anchor,), tier.q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)
    return Target(
        name=f"snova_anchored:{tier.name}",
        P=[GFq(p) for p in P], anchor=anchor_bytes,
        n=tier.n, m=tier.m, q=tier.q, tier=None,
    )


def make_snova_synthetic(seed_pkmap: bytes,
                         tier: SnovaTier = SNOVA_TIER_TOY) -> Target:
    """SNOVA-like Class-C synthetic: anchor injected into one block of P_0.

    Concretely we overwrite the (0, 0) **2x2 block** of every P_i with a
    deterministic 2x2 matrix derived from the i-th anchor byte.  This is
    the SNOVA-shape analogue of the legacy ``synthetic_alg_anchor`` and
    serves as the framework's unit test on the SNOVA family.
    """
    anchor_vec = _gf_uniform(seed_pkmap, b"snova-synth-anchor",
                             (tier.k_anchor,), tier.q)
    anchor_bytes = _pack_anchor_bytes(anchor_vec)

    F = _build_snova_central(seed_pkmap, tier)
    T = _build_block_diagonal_T(seed_pkmap, tier)
    P = _public_block_matrices(F, T, tier.q)

    GFq = get_gf(tier.q)
    leaked = []
    b = tier.block_size
    for i, P_i in enumerate(P):
        P_arr = P_i.copy()
        a = int(anchor_bytes[i % len(anchor_bytes)]) % tier.q
        # Inject `a` into the (0,0) 2x2 block via a fixed pattern.
        P_arr[0:b, 0:b] = np.array(
            [[a, (a + 1) % tier.q],
             [(a + 1) % tier.q, a]],
            dtype=np.int64,
        )
        # Symmetrize on diagonal block (already symmetric by construction).
        leaked.append(GFq(P_arr % tier.q))
    return Target(
        name=f"snova_synthetic:{tier.name}",
        P=leaked, anchor=anchor_bytes,
        n=tier.n, m=tier.m, q=tier.q, tier=None,
    )


SNOVA_LIKE_FACTORIES = {
    "snova_baseline":  make_snova_baseline,
    "snova_anchored":  make_snova_anchored,
    "snova_synthetic": make_snova_synthetic,
}
