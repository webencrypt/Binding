#include "qruov.h"

// C = A*B
#define MATRIX_MUL(N, K, M, A, B, C) {                             \
  int _i,_j,_k ;                                                   \
  _Pragma("omp parallel for private(_i,_j,_k) shared(A, B, C)")    \
  for(_i=0;_i<N;_i++){                                             \
    for(_j=0;_j<M;_j++){                                           \
      Fql_ACC(_t) ;                                                \
      Fql_ACC_ZERO(_t) ;                                           \
      for(_k=0;_k<K;_k++){                                         \
        Fql_ACC_MUL_ADD(A[_i][_k], B[_k][_j], _t) ;                \
      }                                                            \
      Fql_ACC_REDUCE(_t, C[_i][_j]) ;                              \
    }                                                              \
  }                                                                \
}

// C += A*B
#define MATRIX_MUL_ADD(N, K, M, A, B, C) {                         \
  int _i,_j,_k ;                                                   \
  _Pragma("omp parallel for private(_i,_j,_k) shared(A, B, C)")    \
  for(_i=0;_i<N;_i++){                                             \
    for(_j=0;_j<M;_j++){                                           \
      Fql_ACC(_t) ;                                                \
      Fql_ACC_ZERO(_t) ;                                           \
      for(_k=0;_k<K;_k++){                                         \
        Fql_ACC_MUL_ADD(A[_i][_k], B[_k][_j], _t) ;                \
      }                                                            \
      Fql _v ;                                                     \
      Fql_ACC_REDUCE(_t, _v) ;                                     \
      Fql_ADD(_v, C[_i][_j], C[_i][_j]) ;                          \
    }                                                              \
  }                                                                \
}

// C = A+B
#define MATRIX_ADD(N, M, A, B, C) {                          \
  int _i,_j ;                                                \
  _Pragma("omp parallel for private(_i,_j) shared(A, B, C)") \
  for(_i=0;_i<N;_i++){                                       \
    for(_j=0;_j<M;_j++){                                     \
      Fql_ADD(A[_i][_j], B[_i][_j], C[_i][_j]) ;             \
    }                                                        \
  }                                                          \
}

// C = A-B
#define MATRIX_SUB(N, M, A, B, C) {                          \
  int _i,_j ;                                                \
  _Pragma("omp parallel for private(_i,_j) shared(A, B, C)") \
  for(_i=0;_i<N;_i++){                                       \
    for(_j=0;_j<M;_j++){                                     \
      Fql_SUB(A[_i][_j], B[_i][_j], C[_i][_j]) ;             \
    }                                                        \
  }                                                          \
}

// C = A^T
#define MATRIX_TRANSPOSE(N, M, A, C) {                    \
  int _i,_j ;                                             \
  _Pragma("omp parallel for private(_i,_j) shared(A, C)") \
  for(_i=0;_i<N;_i++){                                    \
    for(_j=0;_j<M;_j++){                                  \
      Fql_COPY(A[_i][_j], C[_j][_i]) ;                    \
    }                                                     \
  }                                                       \
}

#define overflow_THRESHOLD                   (1<<(Fql_ws-2*QRUOV_ceil_log_2_q))

#define Fql_ACC(T)                           Fql_acc T ; int overflow_POOL ;
#define Fql_ACC_ZERO(A)                      { A = Fql_acc_zero ; overflow_POOL = 0 ; }

/*
  Assuming random matrices, there is a very small probability of errors
  in matrix operations, since we employed a Monte Carlo algorithm.
  To avoid error, set overflow_DELTA = QRUOV_L+1.
*/

#  if (QRUOV_L== 3)
#  define overflow_DELTA 1
#elif (QRUOV_L==10)
#  define overflow_DELTA 5
#else
#  error "unsupported QRUOV_L"
#endif

#define Fql_ACC_MUL_ADD_0(A,B,C) {                                \
        if(overflow_POOL + overflow_DELTA > overflow_THRESHOLD){  \
          C = Fql_acc_refresh(C) ;                                \
          overflow_POOL = 0 ;                                     \
        } ;                                                       \
        C = Fql_acc_add(C, Fql_acc_mul(A,B)) ;                    \
        overflow_POOL += overflow_DELTA ;                         \
     }

#define Fql_ACC_DOUBLE_0(A,C)    {                                \
        if((overflow_POOL<<1) > overflow_THRESHOLD){              \
          C = Fql_acc_refresh(C) ;                                \
          overflow_POOL = 0 ;                                     \
        } ;                                                       \
        C = Fql_acc_add(C,C) ;                                    \
        overflow_POOL <<= 1 ;                                     \
     }

#define Fql_ACC_MUL_ADD_1(A,B,C) { C = Fql_acc_add(C, Fql_acc_mul(A,B)) ; }
#define Fql_ACC_DOUBLE_1(A,C)    { C = Fql_acc_add(C,C) ; }

#if (QRUOV_V * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)                
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)                
#endif

#define Fql_ACC_REDUCE(A,C)                  { C = Fql_acc_reduce(A) ; }

#define Fql_ACC_DEBUG                        Fql
#define Fql_ACC_ZERO_DEBUG(A)                { A = Fql_zero ; }
#define Fql_ACC_MUL_ADD_DEBUG(A,B,C)         { C = Fql_add(C, Fql_mul(A,B)) ; }
#define Fql_ACC_REDUCE_DEBUG(A,C)            { C = A ; }

#define Fql_ADD(A,B,C)                       { C = Fql_add(A,B) ; }
#define Fql_SUB(A,B,C)                       { C = Fql_sub(A,B) ; }
#define Fql_COPY(A,C)                        { C = A ; }

void VECTOR_M_ADD(const VECTOR_M A, const VECTOR_M B, VECTOR_M C){
  MATRIX_ADD(1, QRUOV_M, ((VECTOR_M *)A), ((VECTOR_M *)B), ((VECTOR_M *)C)) ;
}

void VECTOR_M_SUB(const VECTOR_M A, const VECTOR_M B, VECTOR_M C){
  MATRIX_SUB(1, QRUOV_M, ((VECTOR_M *)A), ((VECTOR_M *)B), ((VECTOR_M *)C)) ;
}

void VECTOR_V_SUB(const VECTOR_V A, const VECTOR_V B, VECTOR_V C){
  MATRIX_SUB(1, QRUOV_V, ((VECTOR_V *)A), ((VECTOR_V *)B), ((VECTOR_V *)C)) ;
}

Fql VECTOR_V_dot_VECTOR_V(const VECTOR_V A, const VECTOR_V B){
  Fql C ;
  MATRIX_MUL(1, QRUOV_V, 1, ((VECTOR_V *)A), ((VECTOR_1 *)B), ((VECTOR_1 *)&C)) ;
  return C ;
}

Fql VECTOR_M_dot_VECTOR_M(const VECTOR_M A, const VECTOR_M B){
  Fql C ;
  MATRIX_MUL(1, QRUOV_M, 1, ((VECTOR_M *)A), ((VECTOR_1 *)B), ((VECTOR_1 *)&C)) ;
  return C ;
}

void VECTOR_V_MUL_MATRIX_VxV(const VECTOR_V A, const MATRIX_VxV B, VECTOR_V C){
  MATRIX_MUL(1, QRUOV_V, QRUOV_V, ((VECTOR_V *)A), B, ((VECTOR_V*)C)) ;
}

void VECTOR_V_MUL_MATRIX_VxM(const VECTOR_V A, const MATRIX_VxM B, VECTOR_M C){
  MATRIX_MUL(1, QRUOV_V, QRUOV_M, ((VECTOR_V *)A), B, ((VECTOR_M *)C)) ;
}

void MATRIX_MUL_MxV_VxV(const MATRIX_MxV A, const MATRIX_VxV B, MATRIX_MxV C){
  // V
  MATRIX_MUL(QRUOV_M, QRUOV_V, QRUOV_V, A, B, C) ;
}

void MATRIX_MUL_MxV_VxM(const MATRIX_MxV A, const MATRIX_VxM B, MATRIX_MxM C){
  // V
  MATRIX_MUL(QRUOV_M, QRUOV_V, QRUOV_M, A, B, C) ;
}

void MATRIX_MUL_ADD_MxV_VxM(const MATRIX_MxV A, const MATRIX_VxM B, MATRIX_MxM C){
  // V
  MATRIX_MUL_ADD(QRUOV_M, QRUOV_V, QRUOV_M, A, B, C) ;
}

void MATRIX_SUB_MxV(const MATRIX_MxV A, const MATRIX_MxV B, MATRIX_MxV C){
  MATRIX_SUB(QRUOV_M, QRUOV_V, A, B, C) ;
}

void MATRIX_ADD_MxM(const MATRIX_MxM A, const MATRIX_MxM B, MATRIX_MxM C){
  MATRIX_ADD(QRUOV_M, QRUOV_M, A, B, C) ;
}

void MATRIX_TRANSPOSE_VxM(const MATRIX_VxM A, MATRIX_MxV C){
  MATRIX_TRANSPOSE(QRUOV_V, QRUOV_M, A, C) ;
}


#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if (QRUOV_M * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)
#endif

void SIG_GEN(VECTOR_M oil, MATRIX_MxV SdT, VECTOR_V vineger, QRUOV_SIGNATURE sig){
  int i,j ;
#pragma omp parallel for private(i,j) shared(oil, SdT, vineger, sig)
  for(i=0;i<QRUOV_V;i++){
    Fql_ACC(t) ;
    Fql_ACC_ZERO(t) ; // M
    for(j=0;j<QRUOV_M;j++){
      Fql_ACC_MUL_ADD(oil[j], SdT[j][i], t) ;
    }
    Fql u ;
    Fql_ACC_REDUCE(t, u) ;
    sig->s[i] = Fql_sub(vineger[i], u) ;
  }
  for(i=QRUOV_V;i<QRUOV_N;i++){
    sig->s[i] = oil[i-QRUOV_V] ;
  }
}

uint8_t VERIFY_i(const MATRIX_VxV Pi1, const MATRIX_MxV Pi2T, const MATRIX_MxM Pi3, const VECTOR_M oil, const VECTOR_V vineger, const Fq msg_i){
  int j,k ;
// #pragma omp parallel for private(j,k) shared(Pi1, P2T, P3, oil, vineger, msg, result)
//  for(i=0; i<QRUOV_m; i++)
  {
    Fql tmp_v [QRUOV_V] ;
    Fql tmp_o [QRUOV_M] ;

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if ((2*QRUOV_M+QRUOV_V) * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)
#endif

    Fql_ACC(t) ;
    for(j=0;j<QRUOV_V;j++){
      Fql_ACC_ZERO(t) ; // 2M+V
      for(k=0;k<QRUOV_M;k++){
        Fql_ACC_MUL_ADD(Pi2T[k][j],oil[k], t) ;
      }
      Fql_ACC_DOUBLE(t, t) ;
      for(k=0;k<QRUOV_V;k++){
        Fql_ACC_MUL_ADD(Pi1[j][k],vineger[k], t) ;
      }
      Fql_ACC_REDUCE(t, tmp_v[j]) ;
    }

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if (QRUOV_M * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)
#endif

    for(j=0;j<QRUOV_M;j++){
      Fql_ACC_ZERO(t) ; // M
      for(k=0;k<QRUOV_M;k++){
        Fql_ACC_MUL_ADD(Pi3[j][k],oil[k],t) ;
      }
      Fql_ACC_REDUCE(t, tmp_o[j]) ;
    }

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if ((QRUOV_V+QRUOV_M) * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)
#endif

    Fql_ACC_ZERO(t) ; // V+M
    for(j=0;j<QRUOV_V;j++){
      Fql_ACC_MUL_ADD(vineger[j],tmp_v[j],t) ;
    }
    for(j=0;j<QRUOV_M;j++){
      Fql_ACC_MUL_ADD(oil[j],tmp_o[j],t) ;
    }
    Fql t_dash ;
    Fql_ACC_REDUCE(t, t_dash) ;
    return msg_i == Fql2Fq(t_dash,QRUOV_perm(0)) ;
  }
}
