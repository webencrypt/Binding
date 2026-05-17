#pragma once
#include "qruov_misc.h"
#include "Fql.h"

typedef uint8_t QRUOV_SEED  [QRUOV_SEED_LEN] ;
typedef uint8_t QRUOV_SALT  [QRUOV_SALT_LEN] ;

TYPEDEF_STRUCT(QRUOV_SIGNATURE,
  QRUOV_SALT r           ;
  Fql        s [QRUOV_N] ;
) ;

typedef Fql        VECTOR_V        [QRUOV_V]        ;
typedef Fql        VECTOR_M        [QRUOV_M]        ;
typedef Fql        VECTOR_1        [      1]        ;

typedef VECTOR_V   MATRIX_VxV      [QRUOV_V]        ;
typedef VECTOR_V   MATRIX_MxV      [QRUOV_M]        ;
typedef VECTOR_M   MATRIX_VxM      [QRUOV_V]        ;
typedef VECTOR_M   MATRIX_MxM      [QRUOV_M]        ;

typedef MATRIX_VxM QRUOV_Sd                         ;
typedef MATRIX_MxV QRUOV_SdT                        ;
typedef MATRIX_VxV QRUOV_P1        [QRUOV_m]        ;
typedef MATRIX_VxM QRUOV_P2        [QRUOV_m]        ;
typedef MATRIX_MxV QRUOV_P2T       [QRUOV_m]        ;
typedef MATRIX_MxM QRUOV_P3        [QRUOV_m]        ;

extern void VECTOR_M_ADD           (const VECTOR_M   A, const VECTOR_M   B, VECTOR_M   C) ;
extern void VECTOR_M_SUB           (const VECTOR_M   A, const VECTOR_M   B, VECTOR_M   C) ;
extern void VECTOR_V_SUB           (const VECTOR_V   A, const VECTOR_V   B, VECTOR_V   C) ;
extern Fql  VECTOR_V_dot_VECTOR_V  (const VECTOR_V   A, const VECTOR_V   B              ) ;
extern Fql  VECTOR_M_dot_VECTOR_M  (const VECTOR_M   A, const VECTOR_M   B              ) ;
extern void VECTOR_V_MUL_MATRIX_VxV(const VECTOR_V   A, const MATRIX_VxV B, VECTOR_V   C) ;
extern void MATRIX_TRANSPOSE_VxM   (const MATRIX_VxM A,                     MATRIX_MxV C) ; // C  = A^T
extern void VECTOR_V_MUL_MATRIX_VxM(const VECTOR_V   A, const MATRIX_VxM B, VECTOR_M   C) ;
extern void MATRIX_MUL_MxV_VxV     (const MATRIX_MxV A, const MATRIX_VxV B, MATRIX_MxV C) ; // C  = A*B
extern void MATRIX_MUL_MxV_VxM     (const MATRIX_MxV A, const MATRIX_VxM B, MATRIX_MxM C) ; // C  = A*B
extern void MATRIX_MUL_ADD_MxV_VxM (const MATRIX_MxV A, const MATRIX_VxM B, MATRIX_MxM C) ; // C += A*B
extern void MATRIX_SUB_MxV         (const MATRIX_MxV A, const MATRIX_MxV B, MATRIX_MxV C) ; // C  = A-B
extern void MATRIX_ADD_MxM         (const MATRIX_MxM A, const MATRIX_MxM B, MATRIX_MxM C) ; // C  = A+B

extern void SIG_GEN(VECTOR_M oil, MATRIX_MxV SdT, VECTOR_V vineger, QRUOV_SIGNATURE sig) ;
extern uint8_t VERIFY_i(const MATRIX_VxV Pi1, const MATRIX_MxV Pi2T, const MATRIX_MxM Pi3, const VECTOR_M oil, const VECTOR_V vineger, const Fq msg_i) ;
