cmake_minimum_required(VERSION 3.10)
project(MQ_PKB C)

# ---------------------------------------------------------------------------
# Source-code artifact for the MQ ownership-gap paper:
#   - MAYO-PKB (digest-tag)            (mayo_a/, over external/mayo-c)
#   - QR-UOV-PKB-T/H + byte-faithful   (qruov_pkb/, over external/qruov-c)
#   - SNOVA-PKB-H + byte-faithful PKB  (snova_a/, over external/snova-c)
#
# The wrappers call the upstream KeyGen/Sign/Vrfy primitives as black
# boxes; no upstream source is patched.  Each "_baseline" target builds
# the corresponding upstream reference unmodified for overhead comparison.
# ---------------------------------------------------------------------------

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -Wall -Wextra -Wno-unused-parameter")

# ===========================================================================
# MAYO-PKB  (NIST L1 + L3, reference and AVX2 paths; digest-tag transform)
# ===========================================================================
set(MAYO_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/mayo-c)
if (EXISTS ${MAYO_C_DIR}/CMakeLists.txt AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mayo_a/src/mayo_a.c)
    set(MAYO_REF_SOURCES
        ${MAYO_C_DIR}/src/mayo.c
        ${MAYO_C_DIR}/src/params.c
        ${MAYO_C_DIR}/src/arithmetic.c
        ${MAYO_C_DIR}/src/common/aes_c.c
        ${MAYO_C_DIR}/src/common/aes128ctr.c
        ${MAYO_C_DIR}/src/common/aes_neon.c
        ${MAYO_C_DIR}/src/common/fips202.c
        ${MAYO_C_DIR}/src/common/mem.c
    )
    set(MAYO_A_SOURCES
        ${MAYO_REF_SOURCES}
        mayo_a/src/mayo_a.c
        mayo_a/src/mayo_a_randombytes.c
    )
    set(MAYO_A_INCLUDES
        mayo_a/include
        ${MAYO_C_DIR}/include
        ${MAYO_C_DIR}/src
        ${MAYO_C_DIR}/src/common
        ${MAYO_C_DIR}/src/generic)
    set(MAYO_A_DEFS ENABLE_PARAMS_DYNAMIC MAYO_BUILD_TYPE_REF)

    # --- MAYO-PKB L1 (reference) ---
    add_executable(test_mayo_a  tests/test_mayo_a.c  ${MAYO_A_SOURCES})
    target_include_directories(test_mayo_a PRIVATE ${MAYO_A_INCLUDES})
    target_compile_definitions(test_mayo_a PRIVATE ${MAYO_A_DEFS})

    add_executable(bench_mayo_a tests/bench_mayo_a.c ${MAYO_A_SOURCES})
    target_include_directories(bench_mayo_a PRIVATE ${MAYO_A_INCLUDES})
    target_compile_definitions(bench_mayo_a PRIVATE ${MAYO_A_DEFS})

    add_executable(kat_mayo_a   tests/kat_mayo_a.c   ${MAYO_A_SOURCES})
    target_include_directories(kat_mayo_a PRIVATE ${MAYO_A_INCLUDES})
    target_compile_definitions(kat_mayo_a PRIVATE ${MAYO_A_DEFS})

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_mayo_baseline.c)
        add_executable(bench_mayo_baseline tests/bench_mayo_baseline.c ${MAYO_A_SOURCES})
        target_include_directories(bench_mayo_baseline PRIVATE ${MAYO_A_INCLUDES})
        target_compile_definitions(bench_mayo_baseline PRIVATE ${MAYO_A_DEFS})
    endif()

    # --- MAYO-PKB L1 (AVX2) ---
    set(MAYO_A_INCLUDES_AVX2
        mayo_a/include
        ${MAYO_C_DIR}/include
        ${MAYO_C_DIR}/src
        ${MAYO_C_DIR}/src/common
        ${MAYO_C_DIR}/src/AVX2
        ${MAYO_C_DIR}/src/generic)
    set(MAYO_A_DEFS_AVX2 MAYO_VARIANT=MAYO_1 MAYO_BUILD_TYPE_AVX2 MAYO_AVX ENABLE_AESNI)
    set(MAYO_A_AVX2_FLAGS -mavx2 -maes -mpclmul -mbmi2 -msse4.2)

    add_executable(bench_mayo_a_avx2 tests/bench_mayo_a.c ${MAYO_A_SOURCES})
    target_include_directories(bench_mayo_a_avx2 PRIVATE ${MAYO_A_INCLUDES_AVX2})
    target_compile_definitions(bench_mayo_a_avx2 PRIVATE ${MAYO_A_DEFS_AVX2})
    target_compile_options(bench_mayo_a_avx2 PRIVATE ${MAYO_A_AVX2_FLAGS})

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_mayo_baseline.c)
        add_executable(bench_mayo_baseline_avx2 tests/bench_mayo_baseline.c ${MAYO_A_SOURCES})
        target_include_directories(bench_mayo_baseline_avx2 PRIVATE ${MAYO_A_INCLUDES_AVX2})
        target_compile_definitions(bench_mayo_baseline_avx2 PRIVATE ${MAYO_A_DEFS_AVX2})
        target_compile_options(bench_mayo_baseline_avx2 PRIVATE ${MAYO_A_AVX2_FLAGS})
    endif()

    # --- MAYO-PKB L3 (reference + AVX2): build-time -DMAYO_A_LEVEL=3 ---
    set(MAYO_A_DEFS_L3       ${MAYO_A_DEFS} MAYO_A_LEVEL=3)
    set(MAYO_A_DEFS_L3_AVX2  MAYO_VARIANT=MAYO_3 MAYO_BUILD_TYPE_AVX2 MAYO_AVX ENABLE_AESNI MAYO_A_LEVEL=3)

    add_executable(test_mayo_a_l3  tests/test_mayo_a.c  ${MAYO_A_SOURCES})
    target_include_directories(test_mayo_a_l3 PRIVATE ${MAYO_A_INCLUDES})
    target_compile_definitions(test_mayo_a_l3 PRIVATE ${MAYO_A_DEFS_L3})

    add_executable(bench_mayo_a_l3 tests/bench_mayo_a.c ${MAYO_A_SOURCES})
    target_include_directories(bench_mayo_a_l3 PRIVATE ${MAYO_A_INCLUDES})
    target_compile_definitions(bench_mayo_a_l3 PRIVATE ${MAYO_A_DEFS_L3})

    add_executable(kat_mayo_a_l3   tests/kat_mayo_a.c   ${MAYO_A_SOURCES})
    target_include_directories(kat_mayo_a_l3 PRIVATE ${MAYO_A_INCLUDES})
    target_compile_definitions(kat_mayo_a_l3 PRIVATE ${MAYO_A_DEFS_L3})

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_mayo_baseline.c)
        add_executable(bench_mayo_baseline_l3 tests/bench_mayo_baseline.c ${MAYO_A_SOURCES})
        target_include_directories(bench_mayo_baseline_l3 PRIVATE ${MAYO_A_INCLUDES})
        target_compile_definitions(bench_mayo_baseline_l3 PRIVATE ${MAYO_A_DEFS_L3})
    endif()

    add_executable(bench_mayo_a_l3_avx2 tests/bench_mayo_a.c ${MAYO_A_SOURCES})
    target_include_directories(bench_mayo_a_l3_avx2 PRIVATE ${MAYO_A_INCLUDES_AVX2})
    target_compile_definitions(bench_mayo_a_l3_avx2 PRIVATE ${MAYO_A_DEFS_L3_AVX2})
    target_compile_options(bench_mayo_a_l3_avx2 PRIVATE ${MAYO_A_AVX2_FLAGS})

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_mayo_baseline.c)
        add_executable(bench_mayo_baseline_l3_avx2 tests/bench_mayo_baseline.c ${MAYO_A_SOURCES})
        target_include_directories(bench_mayo_baseline_l3_avx2 PRIVATE ${MAYO_A_INCLUDES_AVX2})
        target_compile_definitions(bench_mayo_baseline_l3_avx2 PRIVATE ${MAYO_A_DEFS_L3_AVX2})
        target_compile_options(bench_mayo_baseline_l3_avx2 PRIVATE ${MAYO_A_AVX2_FLAGS})
    endif()
else()
    message(STATUS "external/mayo-c or mayo_a/ missing; skipping MAYO-PKB targets.")
endif()

# ===========================================================================
# SNOVA-PKB-H  + byte-faithful PKB-1 witness  (NIST L1, parameter set
# SNOVA-(24,5,16,4); reference path only -- the upstream AVX2/opt paths
# are not part of this artifact).
# ===========================================================================
set(SNOVA_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/snova-c)
if (EXISTS ${SNOVA_C_DIR}/src/snova_ref.c AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/snova_a/src/snova_pkb_h.c)
    set(SNOVA_REF_SOURCES
        ${SNOVA_C_DIR}/src/snova_ref.c
        ${SNOVA_C_DIR}/src/symmetric_ref.c
        ${SNOVA_C_DIR}/src/sign.c
        ${SNOVA_C_DIR}/src/rng.c
        ${SNOVA_C_DIR}/src/aes.c
    )
    set(SNOVA_PKB_SOURCES
        ${SNOVA_REF_SOURCES}
        snova_a/src/snova_pkb_pkdigest.c
        snova_a/src/snova_pkb_h.c
        snova_a/src/snova_pkb_compute_hash.c
    )
    set(SNOVA_PKB_INCLUDES
        snova_a/include
        ${SNOVA_C_DIR}/src
    )
    set(SNOVA_PKB_DEFS
        SNOVA_v=24
        SNOVA_o=5
        SNOVA_q=16
        SNOVA_l=4
        SNOVA_r=4
        SNOVA_OPT=ref
    )
    set(SNOVA_PKB_OPTS -fcommon)

    # --- SNOVA-PKB-H selftest / benchmark / KAT ---
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_snova_pkb.c)
        add_executable(test_snova_pkb tests/test_snova_pkb.c ${SNOVA_PKB_SOURCES})
        target_include_directories(test_snova_pkb PRIVATE ${SNOVA_PKB_INCLUDES})
        target_compile_definitions(test_snova_pkb PRIVATE ${SNOVA_PKB_DEFS})
        target_compile_options(test_snova_pkb PRIVATE ${SNOVA_PKB_OPTS})
    endif()

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_snova_pkb.c)
        add_executable(bench_snova_pkb tests/bench_snova_pkb.c ${SNOVA_PKB_SOURCES})
        target_include_directories(bench_snova_pkb PRIVATE ${SNOVA_PKB_INCLUDES})
        target_compile_definitions(bench_snova_pkb PRIVATE ${SNOVA_PKB_DEFS})
        target_compile_options(bench_snova_pkb PRIVATE ${SNOVA_PKB_OPTS})
    endif()

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/kat_snova_pkb.c)
        add_executable(kat_snova_pkb tests/kat_snova_pkb.c ${SNOVA_PKB_SOURCES})
        target_include_directories(kat_snova_pkb PRIVATE ${SNOVA_PKB_INCLUDES})
        target_compile_definitions(kat_snova_pkb PRIVATE ${SNOVA_PKB_DEFS})
        target_compile_options(kat_snova_pkb PRIVATE ${SNOVA_PKB_OPTS})
    endif()

    # --- Upstream SNOVA baseline (no wrapper, for overhead comparison) ---
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_snova_baseline.c)
        add_executable(bench_snova_baseline tests/bench_snova_baseline.c ${SNOVA_REF_SOURCES})
        target_include_directories(bench_snova_baseline PRIVATE ${SNOVA_PKB_INCLUDES})
        target_compile_definitions(bench_snova_baseline PRIVATE ${SNOVA_PKB_DEFS})
        target_compile_options(bench_snova_baseline PRIVATE ${SNOVA_PKB_OPTS})
    endif()

    # --- Byte-faithful PKB-1 witness on UNMODIFIED upstream SNOVA ---
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/pkb1_attack_snova.c)
        add_executable(pkb1_attack_snova tests/pkb1_attack_snova.c ${SNOVA_PKB_SOURCES})
        target_include_directories(pkb1_attack_snova PRIVATE ${SNOVA_PKB_INCLUDES})
        target_compile_definitions(pkb1_attack_snova PRIVATE ${SNOVA_PKB_DEFS})
        target_compile_options(pkb1_attack_snova PRIVATE ${SNOVA_PKB_OPTS})
    endif()

    # --- SNOVA-PKB-H blocks the byte-faithful PKB-1 attack (100 trials) ---
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/pkb1_attack_snova_pkb_block.c)
        add_executable(pkb1_attack_snova_pkb_block tests/pkb1_attack_snova_pkb_block.c ${SNOVA_PKB_SOURCES})
        target_include_directories(pkb1_attack_snova_pkb_block PRIVATE ${SNOVA_PKB_INCLUDES})
        target_compile_definitions(pkb1_attack_snova_pkb_block PRIVATE ${SNOVA_PKB_DEFS})
        target_compile_options(pkb1_attack_snova_pkb_block PRIVATE ${SNOVA_PKB_OPTS})
    endif()
else()
    message(STATUS "external/snova-c or snova_a/ missing; skipping SNOVA-PKB targets.")
endif()

# ===========================================================================
# QR-UOV-PKB-T / QR-UOV-PKB-H  + byte-faithful PKB-1 witness
# (NIST L1, parameter set qruov1q127L3v156m54).
# Requires OpenSSL libcrypto (for SHAKE/AES via EVP).
# ===========================================================================
set(QRUOV_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/qruov-c)
if (EXISTS ${QRUOV_C_DIR}/src/portable64/qruov.c
    AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/qruov_pkb/src/qruov_pkb_keygen.c)

    find_package(OpenSSL)
    if (OpenSSL_FOUND)
        set(QRUOV_REF_DIR  ${QRUOV_C_DIR}/src/portable64)
        set(QRUOV_GLUE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/qruov_a/portable_glue)
        set(QRUOV_REF_SOURCES
            ${QRUOV_REF_DIR}/Fql.c
            ${QRUOV_REF_DIR}/matrix.c
            ${QRUOV_REF_DIR}/mgf.c
            ${QRUOV_REF_DIR}/qruov.c
            ${QRUOV_REF_DIR}/rng.c
            ${QRUOV_REF_DIR}/sign.c
        )
        set(QRUOV_PKB_SOURCES
            ${QRUOV_REF_SOURCES}
            qruov_pkb/src/qruov_pkb_keygen.c
            qruov_pkb/src/qruov_pkb_pkdigest.c
            qruov_pkb/src/qruov_pkb_t.c
            qruov_pkb/src/qruov_pkb_h.c
        )
        set(QRUOV_PKB_INCLUDES
            qruov_pkb/include
            ${QRUOV_GLUE_DIR}
            ${QRUOV_REF_DIR}
        )

        # QRUOV_HASH_LEGACY: select QR-UOV's pre-Round2 SHA-256-based MGF
        # that uses only public OpenSSL EVP API.  The default Round-2 path
        # needs an OpenSSL-internal symbol (SHA3_squeeze) that is not
        # exported in OpenSSL >=3.x.  This swap is local to our linked-in
        # QR-UOV reference; it does not alter the PKB compiler.
        set(QRUOV_PKB_DEFS QRUOV_HASH_LEGACY)
        set(QRUOV_PKB_OPTS -fcommon -Wno-deprecated-declarations
                           -Wno-unused-result -Wno-unused-function)

        # --- QR-UOV-PKB-T/H selftest / benchmark / KAT ---
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_qruov_pkb.c)
            add_executable(test_qruov_pkb tests/test_qruov_pkb.c ${QRUOV_PKB_SOURCES})
            target_include_directories(test_qruov_pkb BEFORE PRIVATE ${QRUOV_PKB_INCLUDES})
            target_compile_definitions(test_qruov_pkb PRIVATE ${QRUOV_PKB_DEFS})
            target_link_libraries(test_qruov_pkb PRIVATE OpenSSL::Crypto)
            target_compile_options(test_qruov_pkb PRIVATE ${QRUOV_PKB_OPTS})
        endif()

        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_qruov_pkb.c)
            add_executable(bench_qruov_pkb tests/bench_qruov_pkb.c ${QRUOV_PKB_SOURCES})
            target_include_directories(bench_qruov_pkb BEFORE PRIVATE ${QRUOV_PKB_INCLUDES})
            target_compile_definitions(bench_qruov_pkb PRIVATE ${QRUOV_PKB_DEFS})
            target_link_libraries(bench_qruov_pkb PRIVATE OpenSSL::Crypto)
            target_compile_options(bench_qruov_pkb PRIVATE ${QRUOV_PKB_OPTS})
        endif()

        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/kat_qruov_pkb.c)
            add_executable(kat_qruov_pkb tests/kat_qruov_pkb.c ${QRUOV_PKB_SOURCES})
            target_include_directories(kat_qruov_pkb BEFORE PRIVATE ${QRUOV_PKB_INCLUDES})
            target_compile_definitions(kat_qruov_pkb PRIVATE ${QRUOV_PKB_DEFS})
            target_link_libraries(kat_qruov_pkb PRIVATE OpenSSL::Crypto)
            target_compile_options(kat_qruov_pkb PRIVATE ${QRUOV_PKB_OPTS})
        endif()

        # --- Upstream QR-UOV baseline (no wrapper, for overhead comparison) ---
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/bench_qruov_baseline.c)
            add_executable(bench_qruov_baseline tests/bench_qruov_baseline.c ${QRUOV_REF_SOURCES})
            target_include_directories(bench_qruov_baseline BEFORE PRIVATE ${QRUOV_PKB_INCLUDES})
            target_compile_definitions(bench_qruov_baseline PRIVATE ${QRUOV_PKB_DEFS})
            target_link_libraries(bench_qruov_baseline PRIVATE OpenSSL::Crypto)
            target_compile_options(bench_qruov_baseline PRIVATE ${QRUOV_PKB_OPTS})
        endif()

        # --- Byte-faithful PKB-1 witness on UNMODIFIED upstream QR-UOV.
        # This translation unit `#include "qruov.c"` to access the static
        # helpers Expand_mu / Hash / Expand_pk needed by the attack; we
        # therefore EXCLUDE qruov.c from the link to avoid duplicate
        # symbols.  ---
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/pkb1_attack_qruov_demo.c)
            set(PKB1_DEMO_SOURCES
                ${QRUOV_REF_DIR}/Fql.c
                ${QRUOV_REF_DIR}/matrix.c
                ${QRUOV_REF_DIR}/mgf.c
                ${QRUOV_REF_DIR}/rng.c
                tests/pkb1_attack_qruov_demo.c
            )
            add_executable(pkb1_attack_qruov_demo ${PKB1_DEMO_SOURCES})
            target_include_directories(pkb1_attack_qruov_demo BEFORE PRIVATE
                ${QRUOV_GLUE_DIR}
                ${QRUOV_REF_DIR}
            )
            target_compile_definitions(pkb1_attack_qruov_demo PRIVATE ${QRUOV_PKB_DEFS})
            target_link_libraries(pkb1_attack_qruov_demo PRIVATE OpenSSL::Crypto)
            target_compile_options(pkb1_attack_qruov_demo PRIVATE ${QRUOV_PKB_OPTS})
        endif()

        # --- QR-UOV-PKB-H blocks the byte-faithful PKB-1 attack (100 trials).
        # Same trick: this translation unit `#include "qruov.c"`, so we drop
        # qruov.c and sign.c from the link.  ---
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/pkb1_attack_qruov_pkb_block.c)
            set(PKB1_BLOCK_SOURCES
                ${QRUOV_REF_DIR}/Fql.c
                ${QRUOV_REF_DIR}/matrix.c
                ${QRUOV_REF_DIR}/mgf.c
                ${QRUOV_REF_DIR}/rng.c
                qruov_pkb/src/qruov_pkb_keygen.c
                qruov_pkb/src/qruov_pkb_pkdigest.c
                qruov_pkb/src/qruov_pkb_h.c
                tests/pkb1_attack_qruov_pkb_block.c
            )
            add_executable(pkb1_attack_qruov_pkb_block ${PKB1_BLOCK_SOURCES})
            target_include_directories(pkb1_attack_qruov_pkb_block BEFORE PRIVATE
                ${QRUOV_PKB_INCLUDES}
            )
            target_compile_definitions(pkb1_attack_qruov_pkb_block PRIVATE ${QRUOV_PKB_DEFS})
            target_link_libraries(pkb1_attack_qruov_pkb_block PRIVATE OpenSSL::Crypto)
            target_compile_options(pkb1_attack_qruov_pkb_block PRIVATE ${QRUOV_PKB_OPTS})
        endif()
    else()
        message(STATUS "OpenSSL not found; skipping QR-UOV-PKB targets.")
    endif()
else()
    message(STATUS "external/qruov-c or qruov_pkb/ missing; skipping QR-UOV-PKB targets.")
endif()
