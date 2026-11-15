# SDK-free typed-data parsing, hashing and review preparation.
add_library(typeddata
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/typed_data.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/address_format.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mldsa87/keccak256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mldsa87/shake256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mldsa87/keccakf.c
)

target_include_directories(typeddata PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mldsa87
)
