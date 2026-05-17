#ifndef MAYO_A_PARAMS_DISPATCH_H
#define MAYO_A_PARAMS_DISPATCH_H

/* Build-time level dispatcher for MAYO-PKB parameters.
 *
 * Usage: pass -DMAYO_A_LEVEL=1 (default) or -DMAYO_A_LEVEL=3 at compile
 * time.  This header pulls in the matching ``params_mayo_a_lN.h``, which
 * defines all ``MAYO_A_*`` macros at the chosen level.
 *
 * The PKB layer's domain-separation tags are level-agnostic so
 * cross-level digests remain consistent: a fresh d_pk at L3 differs from
 * L1 only because the input pk has different length / contents, not
 * because the tag suffix changed.
 */

#if !defined(MAYO_A_LEVEL)
#  define MAYO_A_LEVEL 1
#endif

#if MAYO_A_LEVEL == 1
#  include "params_mayo_a_l1.h"
#elif MAYO_A_LEVEL == 3
#  include "params_mayo_a_l3.h"
#else
#  error "Unsupported MAYO_A_LEVEL: only 1 (default) and 3 are defined."
#endif

#endif
