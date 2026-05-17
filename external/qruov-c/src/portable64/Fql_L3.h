#pragma once

// ============================================================================
// Fql_reduction
// ============================================================================

inline static Fql Fql_reduction_0(Fql Z){
  uint32_t z0 = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ;
  uint32_t z1 = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ;
  uint32_t z2 =  (uint32_t)Z            ;
  z0 %= QRUOV_q ;
  z1 %= QRUOV_q ;
  z2 %= QRUOV_q ;
  return Fq2Fql_immediate(z0, z1, z2) ;
}

inline static Fql Fql_reduction_2(Fql Z){
  Z = (Z & Fql_mask) + ((Z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
  Fql C  = ((Z+Fql_mask_one) & ~Fql_mask) ;
  return Z + (C>>QRUOV_ceil_log_2_q) - C ;
}

inline static Fql Fql_reduction_1(Fql Z){ return Fql_reduction_0(Z); }

inline static Fql Fql_reduction_debug(Fql Z) ;

// ============================================================================
// Fq^L add/sub
// ============================================================================

inline static Fql Fql_add(Fql X, Fql Y){ return Fql_reduction(X+Y) ; }
inline static Fql Fql_sub(Fql X, Fql Y){ return Fql_reduction(Fql_mask+X-Y) ; }

// ============================================================================
// Fq^L accumulator add/mul
// ============================================================================

inline static Fql_acc Fql_acc_add(Fql_acc X, Fql_acc Y){ return X+Y ; }
inline static Fql_acc Fql_acc_mul(Fql X, Fql Y){ return (Fql_acc)X * (Fql_acc)Y ; }

// ============================================================================
// Fq^L accumulator refresh
// ============================================================================

inline static Fql_acc Fql_acc_refresh_0(Fql_acc Z){
            Z = (Z & Fql_2_acc_mask) + ((Z & ~Fql_2_acc_mask) >> (2*QRUOV_ceil_log_2_q)) ;
            Z = (Z & Fql_acc_mask) + ((Z & ~Fql_acc_mask) >> QRUOV_ceil_log_2_q) ;
            Z = (Z & Fql_acc_mask) + ((Z & ~Fql_acc_mask) >> QRUOV_ceil_log_2_q) ;
  UINT128_T C = ((Z+Fql_acc_mask_one) & ~Fql_acc_mask) ;
  return    Z + (C>>QRUOV_ceil_log_2_q) - C ;
}

inline static Fql_acc Fql_acc_refresh_1(Fql_acc Z){
  uint32_t z0  = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; z0 %= QRUOV_q ;
  uint32_t z1  = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; z1 %= QRUOV_q ;
  uint32_t z2  = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; z2 %= QRUOV_q ;
  uint32_t z3  = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; z3 %= QRUOV_q ;
  uint32_t z4  =  (uint32_t)Z                         ; z4 %= QRUOV_q ;
  return ((Fql_acc)z0            )|
         ((Fql_acc)z1<<(Fql_ws  ))|
         ((Fql_acc)z2<<(Fql_ws*2))|
         ((Fql_acc)z3<<(Fql_ws*3))|
         ((Fql_acc)z4<<(Fql_ws*4));
}

inline static Fql_acc Fql_acc_refresh_debug(Fql_acc Z);

// ============================================================================
// Fq^L accumulator reduce
// ============================================================================

inline static Fql Fql_acc_reduce_2 (Fql_acc Z){
  uint64_t z0 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 1 (14 bit)
  uint64_t z1 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 2
  uint64_t z2 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 3
  uint64_t z3 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 2
  uint64_t z4 =  (uint64_t)Z          ;                // * 1
           z0 += z3                   ;                // * 3
           z1 += z3                   ;                // * 4
           z1 += z4                   ;                // * 5 (14 bit x 5)
           z2 += z4                   ;                // * 4

  uint64_t z = z0|(z1<<(Fql_ws))|(z2<<(Fql_ws*2)) ;
           z = (z & Fql_mask) + ((z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
           z = (z & Fql_mask) + ((z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
           z = (z & Fql_mask) + ((z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;

  uint64_t C = ((z+Fql_mask_one) & ~Fql_mask) ;
  return z + (C>>QRUOV_ceil_log_2_q) - C ;
}

inline static Fql Fql_acc_reduce_1 (Fql_acc Z){
  uint32_t z0 = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; // * 1 (14 bit)
  uint32_t z1 = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; // * 2
  uint32_t z2 = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; // * 3
  uint32_t z3 = ((uint32_t)Z & Fql_wm); Z >>= Fql_ws ; // * 2
  uint32_t z4 =  (uint32_t)Z          ;                // * 1
           z0 += z3                   ;                // * 3
           z1 += z3                   ;                // * 4
           z1 += z4                   ;                // * 5 (14 bit x 5)
           z2 += z4                   ;                // * 4
  z0 %= QRUOV_q ;
  z1 %= QRUOV_q ;
  z2 %= QRUOV_q ;
  return Fq2Fql_immediate(z0, z1, z2) ;
}

inline static Fql Fql_acc_reduce_debug (Fql_acc Z) ;

// inline static Fql Fql_acc_reduce_0(Fql_acc Z){ return Fql_acc_reduce_2(Fql_acc_refresh(Z)) ; }
inline static Fql Fql_acc_reduce_0(Fql_acc Z){ return Fql_acc_reduce_1(Fql_acc_refresh(Z)) ; }

// ============================================================================
// Fq^L mul
// ============================================================================

inline static Fql Fql_mul_0(Fql X, Fql Y){ return Fql_acc_reduce(Fql_acc_mul(X,Y)); }

inline static Fql Fql_mul_1(Fql X, Fql Y){
  UINT128_T Z = (UINT128_T)X * (UINT128_T)Y ;
  Fql Z0, Z1 ;

#  if ((3*Fql_ws) > 64)
  Z0 =  Z ;
  Z1 = (Z >>64) ;
  Z1 >>= (3*Fql_ws - 64) ;
#  else
  Z0  = Z ;
  Z0 &= ((1ULL<<(3*Fql_ws))-1) ;
  Z1  = (Z>>(3*Fql_ws)) ;
#  endif

  Z0 += Z1 ;
  Z1 <<= Fql_ws ;
  Z0 += Z1 ;

#if 1
  Z0 = (Z0 & Fql_mask) + ((Z0 & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
  Z0 = (Z0 & Fql_mask) + ((Z0 & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
  Z0 = (Z0 & Fql_mask) + ((Z0 & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;

  Fql C  = ((Z0+Fql_mask_one) & ~Fql_mask) ;
  return Z0 + (C>>QRUOV_ceil_log_2_q) - C ;
#else
  uint64_t z0 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 1
  uint64_t z1 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 2
  uint64_t z2 = ((uint64_t)Z & Fql_wm); Z >>= Fql_ws ; // * 3
  z0 %= QRUOV_q ;
  z1 %= QRUOV_q ;
  z2 %= QRUOV_q ;
  return Fq2Fql_immediate(z0, z1, z2) ;
#endif
}

inline static Fql Fql_mul_debug(Fql X, Fql Y) ;
