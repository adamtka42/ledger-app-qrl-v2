# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Personal messages of up to 1024 bytes of printable ASCII are signed in the QRL signed-message format through the new `SIGN_PERSONAL_MESSAGE` command (`INS 0x08`), after the account, the byte count and the complete message are reviewed on the device; see `APP_SPECIFICATION.md`
- QRL Typed Structured Data v1 is signed through the new `SIGN_TYPED_DATA` command (`INS 0x0C`). The device validates the type definitions and values, computes the hash itself and shows every field for review; see `APP_SPECIFICATION.md`

### Changed

- The transaction is parsed and Keccak-hashed chunk by chunk as the SIGN_TX APDUs arrive (`src/tx_stream.c`) instead of being buffered and decoded at the end. The fixed 510-byte transaction limit is gone (only a 64 KiB sanity cap remains), so transactions with large calldata can be signed
- Empty SIGN_TX data chunks are rejected with `SW_WRONG_DATA_LENGTH`

### Removed

- `SW_WRONG_TX_LENGTH` (0xB004) is no longer emitted; oversized or malformed input fails with `SW_TX_PARSING_FAIL`
- The whole-buffer RLP decoder (`src/mldsa87/rlp_decode.c`) and its unit test

### Fixed

- A SIGN_TX session becomes active only after the BIP32 path of the first block is validated, and it is discarded when the path, the transaction data or the command parameters are rejected. Continuing a discarded session returns `SW_BAD_STATE` (0xB007)
- Signature chunks are exported only for the currently approved transaction, and only after the signature passed self-verification. An unfinished export of an earlier request no longer authorizes a new one, and the persistent export flag is cleared whenever a request is reset
- First and continuation SIGN_TX blocks with a nonzero P2 are rejected with `SW_WRONG_P1P2`
- A transaction with an empty `to` is reviewed as `Operation: Create contract` instead of a transfer to the zero address
- The derived seed and the secret intermediate buffers of ML-DSA-87 signing and Keccak/SHAKE hashing are wiped after use, also when an operation fails

## [2.1.0] - 2023-10-06

### Changed

- Improving the settings use case in order to be able to use app settings parameters stored in NVM
- add a NBGL use case choice when a setting switch is toggled

## [2.0.0] - 2023-07-10

### Added

- Stax porting
- Extensive CI, including mandatory `guidelines_enforcer.yml`
- Extensive `README.md` to modify/compile/test the application on most OS (Linux, MacOS, Windows)
- Extensive `Ragger` tests

### Changed

- Simplified `Makefile` (complexity delegated to the SDK's `Makefile.standard_app`)
- Simplified overall code (moved into the SDK)
- Improving several UI flows to fit Ledger UI guidelines
- Removing `TRY`/`CATCH` usage (using `_no_throw` SDK functions)
- Cleaning unnecessary resources (moved into the SDK)

### Fixed

- Multiple minor lint, prototype or misspell fixes

## [1.0.1] - 2021-01-11

### Fix

- Missing header includes

## [1.0.0] - 2020-11-19

### Added

- Initial commit with the brand new Boilerplate application
