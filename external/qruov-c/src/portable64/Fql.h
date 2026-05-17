#pragma once
#include "qruov_misc.h"
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
typedef          __int128  INT128_T ;
typedef unsigned __int128 UINT128_T ;

#define Fql_reduction(X)   Fql_reduction_1(X)
#define Fql_acc_refresh(X) Fql_acc_refresh_1(X)
#define Fql_acc_reduce(X)  Fql_acc_reduce_1(X)
#define Fql_mul(X,Y)       Fql_mul_1(X,Y)

// ============================================================================
// F_q  (q = 2^c - 1)
// ============================================================================

typedef uint8_t Fq ;

// ============================================================================
// Fq add/sub ...
// ============================================================================

inline static int Fq_reduction(int Z){
      Z = (Z & QRUOV_q) + ((Z & ~QRUOV_q) >> QRUOV_ceil_log_2_q) ;
  int C = ((Z+1) & ~QRUOV_q) ;
      Z += (C>>QRUOV_ceil_log_2_q) ;
      Z -= C ;
  return Z ;
}

inline static Fq Fq_add(Fq X, Fq Y){ return (Fq)Fq_reduction((int)X+(int)Y) ; }
inline static Fq Fq_sub(Fq X, Fq Y){ return (Fq)Fq_reduction((int)X-(int)Y+QRUOV_q) ; }
inline static Fq Fq_mul(Fq X, Fq Y){ return (Fq)Fq_reduction((int)X*(int)Y) ; }
inline static Fq Fq_inv(Fq X){ extern Fq Fq_inv_table[QRUOV_q] ; return Fq_inv_table[X] ; }

// ============================================================================
// hardware
// ============================================================================
// ws: word size
// wm: word mask

#if QRUOV_L == 3 
#  define Fql_ws               (24)
#  define Fql_wm               ((1ULL<<Fql_ws)-1)
#  define Fql_mask_(n)         (((uint64_t)QRUOV_q)<<(Fql_ws*(n)))
#  define Fql_mask             (Fql_mask_(0)|Fql_mask_(1)|Fql_mask_(2))
#  define Fql_mask_one_(n)     (((uint64_t)1ULL)<<(Fql_ws*(n)))
#  define Fql_mask_one         (Fql_mask_one_(0)|Fql_mask_one_(1)|Fql_mask_one_(2))
#  define Fql_2_mask_(n)       (((uint64_t)((1<<(QRUOV_ceil_log_2_q*2))-1))<<(Fql_ws*(n)))
#  define Fql_2_mask           (Fql_2_mask_(0)|Fql_2_mask_(1)|Fql_2_mask_(2))
#  define Fql_acc_mask_(n)     (((UINT128_T)QRUOV_q)<<(Fql_ws*(n)))
#  define Fql_acc_mask         (Fql_acc_mask_(0)|Fql_acc_mask_(1)|Fql_acc_mask_(2)|Fql_acc_mask_(3)|Fql_acc_mask_(4))
#  define Fql_acc_mask_one_(n) (((UINT128_T)1ULL)<<(Fql_ws*(n)))
#  define Fql_acc_mask_one     (Fql_acc_mask_one_(0)|Fql_acc_mask_one_(1)|Fql_acc_mask_one_(2)|Fql_acc_mask_one_(3)|Fql_acc_mask_one_(4))
#  define Fql_2_acc_mask_(n)   (((UINT128_T)((1<<(QRUOV_ceil_log_2_q*2))-1))<<(Fql_ws*(n)))
#  define Fql_2_acc_mask       (Fql_2_acc_mask_(0)|Fql_2_acc_mask_(1)|Fql_2_acc_mask_(2)|Fql_2_acc_mask_(3)|Fql_2_acc_mask_(4))
#  define Fql_U_SIZE 1
#elif QRUOV_L == 10 
#  define Fql_ws               (16)
#  define Fql_wm               ((1ULL<<Fql_ws)-1)
#  define Fql_mask_(n)         (((uint64_t)QRUOV_q)<<(Fql_ws*(n)))
#  define Fql_mask             (Fql_mask_(0)|Fql_mask_(1)|Fql_mask_(2)|Fql_mask_(3))
#  define Fql_mask_one_(n)     (((uint64_t)1ULL)<<(Fql_ws*(n)))
#  define Fql_mask_one         (Fql_mask_one_(0)|Fql_mask_one_(1)|Fql_mask_one_(2)|Fql_mask_one_(3))
#  define Fql_2_mask_(n)       (((uint64_t)((1<<(QRUOV_ceil_log_2_q*2))-1))<<(Fql_ws*(n)))
#  define Fql_2_mask           (Fql_2_mask_(0)|Fql_2_mask_(1)|Fql_2_mask_(2)|Fql_2_mask_(3))
#  define Fql_U_SIZE 3
#endif
#define Fql_AU_SIZE  (2*(Fql_U_SIZE))

typedef union Fql_union_t {
  uint64_t c64[Fql_U_SIZE*1] ;
  uint32_t c32[Fql_U_SIZE*2] ;
  uint16_t c16[Fql_U_SIZE*4] ;
  uint8_t  c8 [Fql_U_SIZE*8] ;
} Fql_union ;

typedef union Fql_acc_union_t {
  uint64_t  c64[Fql_AU_SIZE*1] ;
  uint32_t  c32[Fql_AU_SIZE*2] ;
  uint16_t  c16[Fql_AU_SIZE*4] ;
  uint8_t   c8 [Fql_AU_SIZE*8] ;
  Fql_union c                  ;
} Fql_acc_union ;

#if QRUOV_L == 3
typedef   uint64_t     Fql ;
typedef   UINT128_T    Fql_acc ;
#  define Fql_zero     ((Fql)0)
#  define Fql_acc_zero ((Fql_acc)0)
#elif QRUOV_L == 10
typedef Fql_union      Fql ;
typedef Fql_acc_union  Fql_acc ;
extern  Fql            Fql_zero ;
extern  Fql_acc        Fql_acc_zero ;
#endif

#if QRUOV_L ==  3
inline static Fq  Fql2Fq(Fql Z, int i){ return ((Z >> ((Fql_ws)*i)) & QRUOV_q) ; }
inline static Fql Fq2Fql_immediate(Fql z0, Fql z1, Fql z2){ return z0|(z1<<Fql_ws)|(z2<<(Fql_ws*2)) ; }
inline static Fql Fq2Fql(uint8_t c[QRUOV_L]){ return Fq2Fql_immediate(c[0],c[1],c[2]) ; }

#elif QRUOV_L == 10
#  if   __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    define WORD_ORDER(i)   (i)
#  elif   __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define WORD_ORDER(i)   (((i>>2)<<2)+(3-(i&3)))
#  else 
#    error "unsupported WORD_ORDER()"
#  endif
inline static Fq  Fql2Fq(Fql Z, int i){ return Z.c16[WORD_ORDER(i)] ; }

inline static Fql Fq2Fql_uint16(uint16_t c[QRUOV_L]){
  Fql Z ;
  Z.c64[Fql_U_SIZE-1] = 0 ;
  for(int i=0; i<QRUOV_L; i++) Z.c16[WORD_ORDER(i)] = c[i] ;
  return Z ;
}

inline static Fql Fq2Fql(uint8_t c[QRUOV_L]){
  Fql Z ;
  Z.c64[Fql_U_SIZE-1] = 0 ;
  for(int i=0; i<QRUOV_L; i++) Z.c16[WORD_ORDER(i)] = c[i] ;
  return Z ;
}

#endif

#if   (QRUOV_q == 127) && (QRUOV_L == 3)
#  include "Fql_L3.h"
#elif (QRUOV_q ==  31) && (QRUOV_L == 3)
#  include "Fql_L3.h"
#elif (QRUOV_q ==  31) && (QRUOV_L == 10)
#  include "Fql_L10.h"
#  include "Fql_q31L10.h"
#elif (QRUOV_q ==   7) && (QRUOV_L == 10)
#  include "Fql_L10.h"
#  include "Fql_q7L10.h"
#else
#  error "unknown (QRUOV_q, QRUOV_L)"
#endif

/* =====================================================================
   memory I/O
   ===================================================================== */

inline static void store_bits(
  int             x,               // \in {0,...,255}
  const int       num_bits,        // \in {0,...,8}
  uint8_t       * pool,            //
  size_t        * pool_bits
){
  int    shift = (int)(*pool_bits &  7) ;
  size_t index = (*pool_bits >> 3) ;
  int    mask  = (1<<num_bits) - 1 ;

  x &= mask ;
  x <<= shift ;
  uint8_t x0 = (x & 0xFF) ;
  if(shift == 0){
    pool[index] = x0 ;
  }else{
    pool[index] |= x0 ;
  }
  if(shift + num_bits > 8){
    uint8_t x1 = (x >> 8) ;
    pool[index+1] = x1 ;
  }

  *pool_bits += (size_t) num_bits ;
}

inline static int restore_bits(     // \in {0,...,255}
  const uint8_t * pool,
  size_t        * pool_bits,
  const int       num_bits          // \in {0,...,8}
){
  int    shift = (int)(*pool_bits &  7) ;
  size_t index = (*pool_bits >> 3) ;
  int    mask  = (1<<num_bits) - 1 ;

  int x        = ((int) pool[index]) 
               | (((shift + num_bits > 8) ? (int)pool[index+1] : 0) << 8) ;
  x >>= shift ;
  x &= mask ; 
  *pool_bits += (size_t) num_bits ;
  return x ;
}

inline static void store_Fq(
  int             x,               // \in Fq
  uint8_t       * pool,
  size_t        * pool_bits
){
  store_bits(x, QRUOV_ceil_log_2_q, pool, pool_bits) ;
}

inline static Fq restore_Fq(
  const uint8_t * pool,
  size_t        * pool_bits
){
  return (Fq) restore_bits(pool, pool_bits, QRUOV_ceil_log_2_q) ;
}

inline static void store_Fq_vector(
  const Fq  * X,
  const int   n,
  uint8_t   * pool,
  size_t    * pool_bits
){
  for(size_t i=0; i<n; i++) store_Fq(X[i], pool, pool_bits) ;
}

inline static void restore_Fq_vector(
  const uint8_t * pool,
  size_t        * pool_bits,
  Fq            * Z,
  const size_t    n
){
  for(size_t i=0; i<n; i++) Z[i] = restore_Fq(pool, pool_bits) ;
}

#if QRUOV_L == 3

inline static void store_Fql(
  Fql       X,
  uint8_t       * pool,            // bit pool
  size_t        * pool_bits        // current bit index
){
  Fq x0 = (Fq)X & QRUOV_q ; X >>= Fql_ws ;
  Fq x1 = (Fq)X & QRUOV_q ; X >>= Fql_ws ;
  Fq x2 = (Fq)X & QRUOV_q ;
  store_Fq(x0, pool, pool_bits) ;
  store_Fq(x1, pool, pool_bits) ;
  store_Fq(x2, pool, pool_bits) ;
}

inline static Fql restore_Fql(
  const uint8_t * pool,            // bit pool
  size_t        * pool_bits        // current bit index
){
  Fql a0 = restore_Fq(pool, pool_bits) ;
  Fql a1 = restore_Fq(pool, pool_bits) ; a1 <<= (Fql_ws) ;
  Fql a2 = restore_Fq(pool, pool_bits) ; a2 <<= (Fql_ws*2) ;
  return a0|a1|a2 ;
}

#elif QRUOV_L == 10

inline static void store_Fql(
  Fql       X,
  uint8_t       * pool,            // bit pool
  size_t        * pool_bits        // current bit index
){
  for(int i=0; i<QRUOV_L; i++){
    Fq x = Fql2Fq(X,i) ;
    store_Fq(x, pool, pool_bits) ;
  }
}

inline static Fql restore_Fql(
  const uint8_t * pool,            // bit pool
  size_t        * pool_bits        // current bit index
){
  uint8_t a[QRUOV_L] ;
  for(int i=0; i<QRUOV_L; i++){
    a[i] = restore_Fq(pool, pool_bits) ;
  }
  return Fq2Fql(a) ;
}
#else
#  error "unsupported QRUOV_L in qruov.h: store_Fql(), restore_Fql()"
#endif

inline static void store_Fql_vector(
  const Fql    * X,
  const size_t   n,
  uint8_t      * pool,
  size_t       * pool_bits
){
  for(size_t i=0; i<n; i++) store_Fql(X[i], pool, pool_bits) ;
}

inline static void restore_Fql_vector(
  const uint8_t * pool,
  size_t        * pool_bits,
  Fql           * Z,
  const size_t    n
){
  for(size_t i=0; i<n; i++) Z[i] = restore_Fql(pool, pool_bits) ;
}
