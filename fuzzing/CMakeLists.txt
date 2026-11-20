cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(FuzzTxParser
        VERSION 1.0
	      DESCRIPTION "Fuzzing of transaction parser"
        LANGUAGES C)

# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzer needs to be built with Clang")
endif()

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

# compatible with ClusterFuzzLite
if (NOT DEFINED ENV{LIB_FUZZING_ENGINE})
	set(FUZZ_COMPILE_FLAGS_ "-g -Wall -fsanitize=fuzzer-no-link,address,undefined")
	set(FUZZ_LINK_FLAGS_ "-fsanitize=fuzzer,address,undefined")
else()
	set(FUZZ_COMPILE_FLAGS_ "$ENV{CFLAGS} $ENV{CXXFLAGS}")
	set(FUZZ_LINK_FLAGS_ "$ENV{CFLAGS} $ENV{CXXFLAGS} $ENV{LIB_FUZZING_ENGINE}")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

string(REPLACE " " ";" FUZZ_COMPILE_FLAGS ${FUZZ_COMPILE_FLAGS_})
string(REPLACE " " ";" FUZZ_LINK_FLAGS ${FUZZ_LINK_FLAGS_})

include(extra/TxParser.cmake)
include(extra/TxFormat.cmake)

target_compile_options(txparser PRIVATE ${FUZZ_COMPILE_FLAGS})
target_compile_options(txformat PRIVATE ${FUZZ_COMPILE_FLAGS})
target_compile_options(txparser PRIVATE -fno-sanitize-recover=undefined)
target_compile_options(txformat PRIVATE -fno-sanitize-recover=undefined)

add_executable(fuzz_tx_parser fuzz_tx_parser.c)

target_compile_options(fuzz_tx_parser PRIVATE ${FUZZ_COMPILE_FLAGS})
target_compile_options(fuzz_tx_parser PRIVATE -fno-sanitize-recover=undefined)
target_link_options(fuzz_tx_parser PRIVATE ${FUZZ_LINK_FLAGS})
target_link_libraries(fuzz_tx_parser PUBLIC txparser)

add_executable(fuzz_tx_format fuzz_tx_format.c)

target_compile_options(fuzz_tx_format PRIVATE ${FUZZ_COMPILE_FLAGS})
target_compile_options(fuzz_tx_format PRIVATE -fno-sanitize-recover=undefined)
target_link_options(fuzz_tx_format PRIVATE ${FUZZ_LINK_FLAGS})
target_link_libraries(fuzz_tx_format PUBLIC txformat)

add_library(contract_call ../src/contract_call.c)
target_include_directories(contract_call PUBLIC ../src)
target_compile_options(contract_call PRIVATE ${FUZZ_COMPILE_FLAGS} -fno-sanitize-recover=undefined)
add_executable(fuzz_contract_call fuzz_contract_call.c)
target_compile_options(fuzz_contract_call PRIVATE ${FUZZ_COMPILE_FLAGS} -fno-sanitize-recover=undefined)
target_link_options(fuzz_contract_call PRIVATE ${FUZZ_LINK_FLAGS})
target_link_libraries(fuzz_contract_call PRIVATE contract_call)

# The staking fuzzer needs a static OpenSSL for its native SHA-256 adapter.
# ClusterFuzzLite must always build it; a local build without static libcrypto
# still gets the other fuzzers.
set(OPENSSL_USE_STATIC_LIBS TRUE)
if (DEFINED ENV{LIB_FUZZING_ENGINE})
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL)
endif()
if (OpenSSL_FOUND)
    add_library(staking_deposit ../src/staking_deposit.c)
    target_include_directories(staking_deposit PUBLIC ../src)
    target_compile_options(staking_deposit PRIVATE ${FUZZ_COMPILE_FLAGS} -fno-sanitize-recover=undefined)
    add_executable(fuzz_staking_deposit fuzz_staking_deposit.c)
    target_compile_options(fuzz_staking_deposit PRIVATE ${FUZZ_COMPILE_FLAGS} -fno-sanitize-recover=undefined)
    target_link_options(fuzz_staking_deposit PRIVATE ${FUZZ_LINK_FLAGS})
    # Only the low-level SHA-256 archive objects are needed by the native adapter.
    # Avoid pkg-config's optional EVP-provider dependencies (e.g. libzstd).
    target_include_directories(fuzz_staking_deposit PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(fuzz_staking_deposit PRIVATE staking_deposit ${OPENSSL_CRYPTO_LIBRARY})
else()
    message(WARNING "Static OpenSSL not found: skipping fuzz_staking_deposit")
endif()
