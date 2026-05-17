#pragma once

// ============================================================================
// Fq^L accumulator reduce
// ============================================================================

inline static Fql Fql_acc_reduce_1(Fql_acc Z){
  uint64_t T2 = Z.c64[2] ;
  uint64_t T3 = Z.c64[3] ;
  uint64_t T4 = Z.c64[4] ;

  uint64_t U3 = (T2>>32) | (T3<<32) ;
  uint64_t U4 = (T3>>32) | (T4<<32) ;
  uint64_t U5 = (T4>>32) ;

  uint64_t V3 =            (U3<<17) ;
  uint64_t V4 = (U3>>47) | (U4<<17) ;
  uint64_t V5 = (T4>>15) ;

  Z.c64[2] &= 0x00000000FFFFFFFFULL ;

  Z.c64[0] += U3 ;
  Z.c64[1] += U4 ;
  Z.c64[2] += U5 ;

  Z.c64[0] += V3 ;
  Z.c64[1] += V4 ;
  Z.c64[2] += V5 ;

  return Fql_reduction(Z.c) ;
}

inline static Fql Fql_acc_reduce_0(Fql_acc Z){return Fql_acc_reduce_1(Fql_acc_refresh(Z));}

inline static Fql Fql_acc_reduce_debug(Fql_acc Z);

// ============================================================================
// Fql_mul
// ============================================================================

inline static Fql Fql_mul_1 (Fql X, Fql Y){
  uint16_t Z[2*QRUOV_L-1] ;
  for(int i=0; i<2*QRUOV_L-1; i++) Z[i] = 0 ;

  for(int i=0; i<QRUOV_L; i++){
    for(int j=0; j<QRUOV_L; j++){
      Z[i+j] += (uint16_t)Fql2Fq(X,i) * (uint16_t)Fql2Fq(Y,j) ;
      // carry ?
    }
  }
  // f(x) = x^L - 2 x - 1
  for(int i=0; i< QRUOV_L-1; i++) Z[i] += Z[i+QRUOV_L] ;
  for(int i=1; i< QRUOV_L  ; i++) Z[i] += Z[i+QRUOV_L-1] * 2 ;
  for(int i=0; i< QRUOV_L  ; i++) Z[i] %= QRUOV_q ;
  return Fq2Fql_uint16(Z) ;
}

inline static Fql Fql_mul_0(Fql X, Fql Y){ return Fql_acc_reduce(Fql_acc_mul(X,Y)) ; }

inline static Fql Fql_mul_debug(Fql X, Fql Y);
