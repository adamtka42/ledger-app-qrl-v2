# Unit tests

## Prerequisite

Be sure to have installed:

- CMake >= 3.10
- CMocka >= 1.1.5

and for code coverage generation:

- lcov >= 1.14

## Overview

In `unit-tests` folder, compile with

```shell
cmake -Bbuild -H. && make -C build
```

and run tests with

```shell
CTEST_OUTPUT_ON_FAILURE=1 make -C build test
```

`test_validate_transaction` exercises the real transaction approval callback
with mocked signing and verification. It checks request/state guards, full
context erasure on rejection or failure, and export only after successful
self-verification, including when an earlier signature export was unfinished.
The device regression tests in `tests/test_sign_cmd.py` also reject stale
signature export after a new first block and after receiving partial data.
The shared request reset is checked for clearing the persistent export flag
after cancellation/restart, preserving settings and buffers, and avoiding NVM
writes when the flag is already clear.

`test_transaction_review` exercises the real review and approval callbacks with
injected address-derivation, formatting, signing and verification failures.
It checks that failed preparation clears the session and returns to the home
screen, and that clear/blind reviews show a failure instead of a signed status
when signing or self-verification fails.

`test_personal_message_review` exercises the production NBGL callback with a small
reusable cache. It checks full message reconstruction, backwards/indexed retrieval,
stale-session rejection, approval/rejection statuses and returning to the home
screen before reporting review-preparation errors. A Nano target additionally
checks that its entire message is passed as one value; the touch target exercises
fallback when a candidate page would need details. The UI no longer reserves
arrays for every fragment's label and tag/value pair.

`test_personal_message` checks QRL SDK hash vectors, every streaming split,
text/length limits and lossless conversion of the full message into review
fragments, including the empty message and maximum newline count. Device tests
in `tests/test_personal_message_cmd.py` additionally cover approval/rejection,
ML-DSA verification, malformed APDUs and isolation from transaction sessions.

`test_typed_data` checks QRL VM64 typed-data digests against the fixtures in
`fixtures/typed_data.txt`, cross-checked with go-qrl's `TypedDataAndHash`.
It covers nested structs, arrays, 512-bit integers, empty/long values, all
streaming split positions, truncation, trailing bytes and canonical values.
`tests/test_typed_data_cmd.py` additionally checks UI, signatures, malformed
schemas, review limits and isolation from transaction/personal-message sessions.
`test_typed_storage` observes NVM writes and checks raw-payload erasure, review
erasure, replacement/startup cleanup, and retry after interrupted erasure.

`test_tx_stream` also checks retained calldata prefixes for arbitrary lengths,
including buffer boundaries and larger streamed payloads, across APDU splits.
`test_token_transfer` covers the 64-byte QRVM transfer/approve ABI, every transaction
split point, token/network binding, metadata parsing, and exact amount formatting.
It also distinguishes limited, zero/revoked and unlimited approvals.
`test_transaction_builder` checks the shared Python RLP builder against existing
native/token transaction vectors and canonical length/integer boundaries. It runs
without an emulator or third-party Python packages.
`test_token_metadata_key` checks build-time issuer key validation, including
off-curve points, coordinate ranges, malformed encodings, and the test-key gate.
It requires Python 3 and can also run with `python3 unit-tests/test_token_metadata_key.py`
from the repository root.
Device tests in `tests/test_token_transfer_cmd.py` and `tests/test_token_approval_cmd.py` verify real
metadata signatures and ML-DSA transaction signatures in Speculos. Positive
device tests require `DEBUG=1 TOKEN_METADATA_TEST_KEY=1` and should run with
`--token-metadata-test-key` so a missing issuer fails rather than skips; see
`APP_SPECIFICATION.md` for issuer configuration and the APDU sequence.

## Generate code coverage

Just execute in `unit-tests` folder

```shell
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).
