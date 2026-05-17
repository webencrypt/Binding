#pragma once

// ============================================================================
// Fql_reduction
// ============================================================================

inline static Fql Fql_reduction_0(Fql Z){
  int i ;
  for(i=0;i<QRUOV_L        ;i++) Z.c16[WORD_ORDER(i)] %= QRUOV_q ;
  for(   ;i<(Fql_U_SIZE<<2);i++) Z.c16[WORD_ORDER(i)]  = 0 ;
  return Z ;
}

inline static Fql Fql_reduction_1(Fql z){
  int l ;
  for(l=0;l<3;l++){
    uint64_t Z = z.c64[l] ;
#if QRUOV_q == 7
             Z = (Z & Fql_2_mask) + ((Z & ~Fql_2_mask) >> (2*QRUOV_ceil_log_2_q)) ;
#elif QRUOV_q == 31
             Z = (Z & Fql_mask) + ((Z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
#endif
             Z = (Z & Fql_mask) + ((Z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
             Z = (Z & Fql_mask) + ((Z & ~Fql_mask) >> QRUOV_ceil_log_2_q) ;
    uint64_t C  = ((Z+Fql_mask_one) & ~Fql_mask) ;
    z.c64[l] = Z + (C>>QRUOV_ceil_log_2_q) - C ;
  }
  z.c64[2] &= 0x00000000FFFFFFFFULL ;
  return z ;
}

inline static Fql Fql_reduction_debug(Fql Z);

// ============================================================================
// Fq^L add/sub
// ============================================================================

inline static Fql Fql_add(Fql X, Fql Y){
  Fql Z ;
  for(int k=0; k < Fql_U_SIZE; k++) Z.c64[k] = X.c64[k] + Y.c64[k] ;
  return Fql_reduction(Z) ;
}

inline static Fql Fql_sub(Fql X, Fql Y){
  Fql Z ;
  for(int k=0; k < Fql_U_SIZE; k++) Z.c64[k] = Fql_mask + X.c64[k] - Y.c64[k] ;
  return Fql_reduction(Z) ;
}

// ============================================================================
// Fq^L accumulator add/mul
// ============================================================================

inline static Fql_acc Fql_acc_add(Fql_acc X, Fql_acc Y) {
  for(int i=0; i<Fql_AU_SIZE; i++) X.c64[i] += Y.c64[i] ;
  return X ;
}

#if 0
inline static Fql_acc Fql_acc_mul(Fql X, Fql Y){
  Fql_acc Z = Fql_acc_zero ;
  for(int i=0; i<Fql_U_SIZE; i++){
    for(int j=0; j<Fql_U_SIZE; j++){
      UINT128_T ZZ = (UINT128_T) X.c64[i] * (UINT128_T) Y.c64[j] ;
      Z.c64[i+j] += (uint64_t)ZZ;
      Z.c64[i+j+1] += (uint64_t)(ZZ>>64) ;
    }
  }
  return Z ;
}
#else
inline static Fql_acc Fql_acc_mul(Fql X, Fql Y){
  Fql_acc Z = Fql_acc_zero ;
  int i,j ;
  for(i=0; i<Fql_U_SIZE-1; i++){
    for(j=0; j<Fql_U_SIZE; j++){
      UINT128_T ZZ = (UINT128_T) X.c64[i] * (UINT128_T) Y.c64[j] ;
      Z.c64[i+j] += (uint64_t)ZZ;
      Z.c64[i+j+1] += (uint64_t)(ZZ>>64) ;
    }
  }
  for(j=0; j<Fql_U_SIZE-1; j++){
    UINT128_T ZZ = (UINT128_T) X.c64[i] * (UINT128_T) Y.c64[j] ;
    Z.c64[i+j] += (uint64_t)ZZ;
    Z.c64[i+j+1] += (uint64_t)(ZZ>>64) ;
  }
  uint64_t ZZ = (uint64_t) X.c64[i] * (uint64_t) Y.c64[j] ;
  Z.c64[i+j] += (uint64_t)ZZ;

  return Z ;
}
#endif

// ============================================================================
// Fq^L accumulator refresh
// ============================================================================

inline static Fql_acc Fql_acc_refresh_1(Fql_acc Z){
  int i ;
  for(i=0;i<(2*QRUOV_L-1   );i++) Z.c16[WORD_ORDER(i)] %= QRUOV_q ;
  for(   ;i<(Fql_AU_SIZE<<2);i++) Z.c16[WORD_ORDER(i)]  = 0 ;
  return Z ;
}

#define Fql_acc_refresh_0(Z) Fql_acc_refresh_1(Z)

inline static Fql_acc Fql_acc_refresh_debug(Fql_acc Z);
