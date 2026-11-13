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

## Generate code coverage

Just execute in `unit-tests` folder

```shell
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).
