#pragma once

// ============================================================================
// Fq^L accumulator reduce
// ============================================================================

inline static Fql Fql_acc_reduce_2(Fql_acc Z){
  uint64_t T2 = Z.c64[2] ;
  uint64_t T3 = Z.c64[3] ;
  uint64_t T4 = Z.c64[4] ;

  uint64_t U3 = (T2>>32) | (T3<<32) ;
  uint64_t U4 = (T3>>32) | (T4<<32) ;
  uint64_t U5 = (T4>>32) ;

  uint64_t V3 =            (U3<<48) ;
  uint64_t V4 = (U3>>16) | (U4<<48) ;
  uint64_t V5 = (U4>>16) | (U5<<48) ;

  uint64_t W3 = V3 * 5 ;
  uint64_t W4 = V4 * 5 ;
  uint64_t W5 = V5 * 5 ;

  uint64_t S3 = (W5>>32) ;
  uint64_t S4 = S3 * 5 ;
           S3 |= (S4<<48) ;
           S4 >>= 16 ;

  Z.c64[0] += U3 ;
  Z.c64[1] += U4 ;
  Z.c64[2] += U5 ;

  Z.c64[0] += W3 ;
  Z.c64[1] += W4 ;
  Z.c64[2] += W5 ;

  Z.c64[0] += S3 ;
  Z.c64[1] += S4 ;
  Z.c64[2] &= 0x00000000FFFFFFFFULL ;

  return Fql_reduction(Z.c) ;
}

inline static Fql Fql_acc_reduce_0(Fql_acc Z){return Fql_acc_reduce_2(Fql_acc_refresh(Z));}
inline static Fql Fql_acc_reduce_1(Fql_acc Z){return Fql_acc_reduce_0(Z);}

inline static Fql Fql_acc_reduce_debug(Fql_acc Z);

// ============================================================================
// Fql_mul 
// ============================================================================

inline static Fql Fql_mul_1(Fql X, Fql Y){
  uint32_t Z[QRUOV_L*2-1] ;
  for(int i=0; i<QRUOV_L*2-1; i++) Z[i] = 0 ;

  for(int i=0; i<QRUOV_L; i++){
    for(int j=0; j<QRUOV_L; j++){
      Z[i+j] += (uint32_t)Fql2Fq(X,i) * (uint32_t)Fql2Fq(Y,j) ;
    }
  }
  // f(x) = x^L - 5 x^3 - 1
  for(int i=0; i<=8; i++) Z[i] +=    Z[i+10] ;
  for(int i=3; i<=9; i++) Z[i] +=  5*Z[i+ 7] ;
  for(int i=0; i<=1; i++) Z[i] +=  5*Z[i+17] ;
  for(int i=3; i<=4; i++) Z[i] += 25*Z[i+14] ;

  uint8_t z[QRUOV_L] ;
  for(int i=0; i<QRUOV_L; i++) z[i] = (Z[i] % QRUOV_q) ;
  return Fq2Fql(z) ;
}

inline static Fql Fql_mul_0(Fql X, Fql Y){ return Fql_acc_reduce_1(Fql_acc_mul(X,Y)) ; }

inline static Fql Fql_mul_debug(Fql X, Fql Y);
