cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
        DESCRIPTION "Unit tests for the QRL v2.0 Ledger application"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -Werror -pedantic -g -O0 --coverage -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS} -fsanitize=address,undefined -fno-sanitize-recover=undefined")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(TEST)

include_directories(../src)
include_directories(../src/mldsa87)
include_directories(../src/ui)

add_executable(test_tx_format test_tx_format.c)
add_executable(test_hash_kat test_hash_kat.c)
add_executable(test_address_format test_address_format.c)

add_library(tx_format ../src/ui/tx_format.c)
# One shared Keccak-f permutation behind all three sponges.
add_library(hashes ../src/mldsa87/keccakf.c
                   ../src/mldsa87/keccak256.c
                   ../src/mldsa87/shake128.c
                   ../src/mldsa87/shake256.c)
add_library(address_format ../src/address_format.c)

target_link_libraries(test_tx_format PUBLIC tx_format cmocka gcov)
add_test(test_tx_format test_tx_format)

target_link_libraries(test_hash_kat PUBLIC hashes cmocka gcov)
add_test(test_hash_kat test_hash_kat)

target_link_libraries(test_address_format PUBLIC address_format hashes cmocka gcov)
add_test(test_address_format test_address_format)

# streaming parser (tx_stream.c depends only on tx_types.h, no SDK headers)
add_executable(test_tx_stream test_tx_stream.c)
add_library(tx_stream ../src/tx_stream.c)
target_link_libraries(test_tx_stream PUBLIC tx_stream cmocka gcov)
add_test(test_tx_stream test_tx_stream)

add_executable(test_validate_transaction
    test_validate_transaction.c
    ../src/ui/action/validate.c
    ../src/helper/request_context.c)
target_include_directories(test_validate_transaction BEFORE PRIVATE mocks ../src/helper ../src/ui/action)
target_link_libraries(test_validate_transaction PRIVATE cmocka gcov)
add_test(test_validate_transaction test_validate_transaction)

add_executable(test_transaction_review
    test_transaction_review.c
    ../src/ui/nbgl_display_transaction.c
    ../src/ui/action/validate.c
    ../src/helper/request_context.c)
target_include_directories(test_transaction_review BEFORE PRIVATE mocks ../src/helper ../src/ui/action)
target_compile_definitions(test_transaction_review PRIVATE TARGET_FLEX SCREEN_SIZE_WALLET)
set_property(TARGET test_transaction_review APPEND_STRING PROPERTY LINK_FLAGS
    " -Wl,--wrap=format_checksummed_address,--wrap=format_qrl_amount,--wrap=multiply_uint8_arrays,--wrap=uint8_array_to_decimal")
target_link_libraries(test_transaction_review PRIVATE tx_format address_format hashes cmocka gcov)
add_test(test_transaction_review test_transaction_review)

add_library(token_call ../src/token_call.c)
add_executable(test_token_transfer test_token_transfer.c)
target_link_libraries(test_token_transfer PUBLIC token_call tx_stream tx_format cmocka gcov)
add_test(test_token_transfer test_token_transfer)

# Validate the real Makefile's issuer configuration using only Python's stdlib.
find_program(TOKEN_METADATA_TEST_PYTHON NAMES python3)
if(NOT TOKEN_METADATA_TEST_PYTHON)
    message(FATAL_ERROR "Python 3 is required for token metadata key tests")
endif()
add_test(NAME test_token_metadata_key
         COMMAND ${TOKEN_METADATA_TEST_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/test_token_metadata_key.py)
add_test(NAME test_transaction_builder
         COMMAND ${TOKEN_METADATA_TEST_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/test_transaction_builder.py)

# Exercise real crypto code with mocked Ledger syscalls and observed erasure.
add_executable(test_crypto_cleanup
    test_crypto_cleanup.c
    ../src/address.c
    ../src/mldsa87/mldsa87.c
    ../src/mldsa87/sign.c
    ../src/mldsa87/poly.c
    ../src/mldsa87/polyvec.c
    ../src/mldsa87/ntt.c
    ../src/mldsa87/reduce.c
    ../src/mldsa87/rounding.c
    ../src/mldsa87/constant.c
    ../src/mldsa87/utils.c
    ../src/mldsa87/keccakf.c
    ../src/mldsa87/shake128.c
    ../src/mldsa87/shake256.c)
target_include_directories(test_crypto_cleanup BEFORE PRIVATE mocks)
target_compile_definitions(test_crypto_cleanup PRIVATE explicit_bzero=test_explicit_bzero)
set_property(TARGET test_crypto_cleanup APPEND_STRING PROPERTY LINK_FLAGS
    " -Wl,--wrap=shake256_absorb,--wrap=shake256_squeeze,--wrap=poly_vec_l_uniform_eta,--wrap=poly_vec_k_uniform_eta,--wrap=poly_vec_l_chk_norm")
target_link_libraries(test_crypto_cleanup PRIVATE cmocka gcov)
add_test(test_crypto_cleanup test_crypto_cleanup)

# Approval review uses token-call classification helpers.
target_link_libraries(test_transaction_review PRIVATE token_call)
