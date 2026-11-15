# Technical Specification

## About

This documentation describes the APDU messages interface to communicate with the QRL v2.0 application.

The application covers the following functionalities :

- Get a public QRL v2.0 address given a BIP 32 path
- Sign a QRL v2.0 transaction given a BIP 32 path and RLP encoded transaction data
- Retrieve the QRL v2.0 app version
- Retrieve the QRL v2.0 app name

The application interface can be accessed over HID or BLE

## APDUs

### GET QRL v2.0 PUBLIC ADDRESS

#### Description

This command returns the public QRL v2.0 address for the given BIP 32 path.

The address can be verified on the device before being returned.

#### Coding

##### `Command`

| CLA | INS   | P1   | P2    | Lc  |
| --- | ---   | ---  | ---   | --- |
| E0  |  05   |  01  | 00    | 21  | 

##### `Input data`

| Description                                                      | Length |
| ---                                                              | ---    |
| Number of BIP 32 derivations to perform (always 5)               | 1      |
| Purpose (`0x8000002C`)                                           | 4      |
| Coin type (`0x800000EE`)                                         | 4      |
| Account                                                          | 4      |
| Change                                                           | 4      |
| Address                                                          | 4      |

##### `Output data`

| Description                                                      | Length |
| ---                                                              | ---    |
| Prefix (`Q`)                                                     | 1      |
| Address                                                          | 64     |

### SIGN QRL v2.0 TRANSACTION

#### Description

This command signs a QRL v2.0 transaction after having the user validate the transactions parameters.

The signing session becomes active only after the first block's BIP32 path has
been validated. Transaction data blocks (`P1=01` or `P1=02, P2=00`) are accepted
only while that session is receiving data. If the signing handler rejects a
path, transaction data, or command parameters, the session is discarded. The
host must send a new first block before retrying; continuing a discarded session
returns `SW_BAD_STATE` (`B007`). A new first block also replaces any previous
signing session, including when the new path is empty or malformed.

First and continuation blocks (`P1=00/01`) require `P2=00`. Signature export
uses `P1=02, P2=01..11` (hexadecimal) with an empty payload and is authorized
only for the current approved transaction after successful signature
self-verification. An unfinished export from a previous request does not
authorize a new receiving session. Rejected or failed signing requests are
discarded before returning their status word.

Resetting a request also clears the persistent signature-export flag. This
happens on app startup, when a new signing or public-key request replaces the
old session, and when a signing request fails or is rejected. An already clear
flag is not written again, avoiding unnecessary NVM writes. Session-state
checks remain mandatory independently of this flag.

The input data is the RLP encoded transaction streamed to the device in 255 bytes maximum data chunks. The device parses and hashes the transaction incrementally as the chunks arrive, so there is no fixed maximum transaction size (only a 64 KiB sanity cap applies).

As the signature size exceeds maximum APDU response length, responses will be chunked with max size of 258 bytes each. The main app should request each chunk manually with index from 0-17, where the first chunk will be automatically returned after the last transaction data is sent and the signature is computed.

#### Coding

##### `Command`

| CLA | INS  | P1                   | P2                               | Lc       |
| --- | ---  | ---                  | ---                              | ---      |
| E0  | 06   | 00 : first data (BIP32 path) | 00 | variable |
| E0  | 06   | 01 : more tx data | 00 | variable |
| E0  | 06   | 02 : last tx data | 00 | variable |
| E0  | 06   | 02 : retrieve signature chunk | 01..11 (hex, chunks 1..17) | 00 |

##### `Input data (first transaction data block)`

| Description                                                      | Length |
| ---                                                              | ---    |
| Number of BIP 32 derivations to perform (always 5)               | 1      |
| Purpose (`0x8000002C`)                                           | 4      |
| Coin type (`0x800000EE`)                                         | 4      |
| Account                                                          | 4      |
| Change                                                           | 4      |
| Address                                                          | 4      |

##### `Input data (other transaction data block)`

| Description                                          | Length   |
| ---                                                  | ---      |
| Transaction chunk                                    | variable |

##### `Input data (request more signature chunk)`

None

##### `Output data`

| Description                                          | Length   |
| ---                                                  | ---      |
| Signature                                            | variable |

### GET APP VERSION

#### Description

This command returns QRL v2.0 application version

#### Coding

##### `Command`

| CLA | INS | P1  | P2  | Lc   |
| --- | --- | --- | --- | ---  |
| E0  | 03  | 00  | 00  | 00   |

##### `Input data`

None

##### `Output data`

| Description                       | Length |
| ---                               | ---    |
| Application major version         | 1      |
| Application minor version         | 1      |
| Application patch version         | 1      |

### GET APP NAME

#### Description

This command returns QRL v2.0 application name

#### Coding

##### `Command`

| CLA | INS | P1  | P2  | Lc   |
| --- | --- | --- | --- | ---  |
| E0  | 04  | 00  | 00  | 00   |

##### `Input data`

None

##### `Output data`

| Description           | Length   |
| ---                   | ---      |
| Application name      | variable |

### PROVIDE TOKEN METADATA

Accepts one authenticated token descriptor for the current transaction session.
It must be sent **after** `SIGN_TX/DATA_FIRST` and **before** any transaction bytes:

1. `SIGN_TX`, P1=`00`, P2=`00`: BIP32 path.
2. `PROVIDE_TOKEN_METADATA`, CLA=`E0`, INS=`0A`, P1=`00`, P2=`00`: payload below.
3. Existing `SIGN_TX/DATA_MORE` and `SIGN_TX/DATA_LAST`: unchanged transaction bytes.

| Payload field | Bytes | Encoding |
| --- | --- | --- |
| Version | 1 | `01` |
| Chain ID | 32 | Unsigned big-endian, left-padded with zeros; nonzero |
| Token contract | 64 | Raw QRL address bytes, without textual `Q`; nonzero |
| Decimals | 1 | `0` through `77` |
| Symbol length | 1 | `1` through `12` |
| Symbol | variable | ASCII letters, digits, `.`, `_`, `-`; no NUL/whitespace; never `QRL` in any letter case |
| Signature | 8–72 | DER ECDSA P-256 signature |

Issuers must attest only fungible SQRCTF1-compatible contracts on the specified
network. This payload has no token-standard discriminator: ERC-721 uses the same
`approve(address,uint256)` selector (`095ea7b3`), but the integer is a token ID,
not a spending limit. The device cannot distinguish these semantics from
calldata alone; issuers must not sign these descriptors for NFT contracts.

The issuer signs `SHA256(ASCII("QRL-TOKEN-METADATA-V1") || body)`, where `body`
contains every field from Version through Symbol. There is no NUL separator.
The complete payload fits in one short APDU. A malformed or unauthenticated
descriptor aborts the signing session. It is never accepted as unsigned metadata.

The issuer's uncompressed 65-byte P-256 public key is set at build time:

```sh
make TOKEN_METADATA_PUBLIC_KEY=<130-hex-character-SEC1-public-key>
```

The build requires 130 hex characters starting with `04`, checks that the
coordinates form a valid P-256 point, and rejects the public test key. Validation
uses Python 3's standard library and stops the build on an invalid key.

No production authority is configured by default: the metadata command returns
`6A88` (`SW_TOKEN_METADATA_NO_ISSUER`), while existing native transfers and blind signing remain available.
The issuer must curate tokens, ABI profiles, and stable symbol/decimals bindings.
An issuer backend and wallet integration must provide signed QRL descriptors;
Ethereum's existing 20-byte token metadata is not compatible with this payload.
This release uses classical ECDSA for metadata authentication; QRL transaction
signatures remain ML-DSA-87. A post-quantum metadata authority would require a
versioned extension of this format and its verification implementation.

For emulator tests only:

```sh
make DEBUG=1 TOKEN_METADATA_TEST_KEY=1
pytest --device nanosp --token-metadata-test-key tests/test_token_transfer_cmd.py
```

The test issuer uses the publicly known P-256 scalar `1`, requires `DEBUG=1`, and
displays `TEST token transfer` during review. The same key is rejected when
provided as a production key. Never deploy the test-authority build for funds.
Positive metadata tests skip only when the app reports no configured issuer.
With `--token-metadata-test-key`, this response fails the test instead; invalid
signatures always fail fixture setup. Negative authentication tests still run. Tests use synthetic contracts, not a
claim that a real token has been approved or deployed on a particular network.

#### Supported clear-signed calls

`transfer(address,uint256)` and `approve(address,uint256)` are decoded:

- Selector: `a9059cbb` for transfer, `095ea7b3` for approve (4 bytes).
- Recipient or spender: one 64-byte QRVM ABI word; approve requires a nonzero spender.
- Amount: one 64-byte word, with the upper 32 bytes zero (`uint256`).
- Exact calldata length: 132 bytes; no additional bytes. The RLP parser retains
  the first 256 calldata bytes for operation decoders and records the full length;
  larger payloads continue to be streamed and hashed. This storage limit does not
  broaden the supported clear-signing profile.
- Token contract and full Chain ID must match the verified descriptor.
- Native QRL value must be zero; access list must be empty.

The screen shows the sending account, token amount/symbol, actual token
recipient, token contract, Chain ID, and maximum fees in QRL, plus optional nonce
and transaction hash. The token contract row is titled `Token contract`, or
`Contract` on Nano, where the longer title does not fit. The signature covers the original complete transaction,
including calldata. Recognition does not simulate execution or guarantee a
successful transfer or the amount ultimately credited by a custom token.

Approvals have a separate review: Owner, Spending limit, Spender, Token contract,
Chain ID and QRL fees, plus optional nonce and transaction hash. A zero limit
is presented as revocation in the review. Exactly `2^256 - 1` is displayed as
`<symbol> Unlimited` with an explicit unlimited-spending confirmation on all
four supported models, including Nano S+ and Nano X; smaller
values always retain their exact numeric limit. Approval sets the new allowance
and does not transfer tokens. The device neither queries the current allowance
nor guarantees execution. Issuers must only attest fungible SQRCTF1-compatible
contracts; the approve selector alone also exists in other token standards.

Zero-address policy: token transfers retain the existing literal-recipient review,
including a zero recipient, to preserve transfer compatibility. This is not a
claim that the call succeeds, and the review does not infer a burn: standard
SQRCTF1 contracts revert such transfers. Approvals use a stricter supported profile
and require a nonzero spender; a zero spender is not a revoke-all instruction.
Revocation is `approve(nonzero_spender, 0)`. This approval feature does not
change the established transfer policy or simulate contract execution.

Other calls, mismatching descriptors, noncanonical token arguments, native
value, or nonempty access lists follow the existing blind-signing policy; with
blind signing disabled they are rejected. `transferFrom`, NFT calls,
routers, and general ABI decoding are outside this version's supported profile.

Descriptors exist only in RAM for one signing session. `DATA_FIRST`, address
requests, and aborted sessions invalidate them; none are persisted to NVM or
reused automatically. Signature chunks additionally require an approved session.

See `tests/application_client/token_metadata.py` for payload generation and
`examples/token_call.py` for an interactive Speculos example.

For manual approval review (no transaction is broadcast):

```sh
tests/venv/bin/python examples/token_call.py --test-key --operation approve --units 25000000
tests/venv/bin/python examples/token_call.py --test-key --operation approve --units 0
tests/venv/bin/python examples/token_call.py --test-key --operation approve --unlimited
```

Use `--url` for the emulator API endpoint and `--spender Q...` to change the
authorized spender. The metadata APDU and session ordering remain unchanged.

## Status Words

The following standard Status Words are returned for all APDUs.

| SW       | SW name                     | Description                                           |
| ---      | ---                         | ---                                                   |
|   6985   | SW_DENY                     | Rejected by user                                      |
|   6982   | SW_TOKEN_METADATA_UNTRUSTED  | Token metadata authentication failed                   |
|   6A80   | SW_TOKEN_METADATA_INVALID   | Malformed or unsupported token descriptor              |
|   6A86   | SW_WRONG_P1P2               | Either P1 or P2 is incorrect                          |
|   6A87   | SW_WRONG_DATA_LENGTH        | Lc or minimum APDU length is incorrect                |
|   6A88   | SW_TOKEN_METADATA_NO_ISSUER | No token metadata authority configured                |
|   6D00   | SW_INS_NOT_SUPPORTED        | No command exists with INS                            |
|   6E00   | SW_CLA_NOT_SUPPORTED        | Bad CLA used for this application                     |
|   B000   | SW_WRONG_RESPONSE_LENGTH    | Wrong response length (buffer size problem)           |
|   B001   | SW_DISPLAY_BIP32_PATH_FAIL  | BIP32 path conversion to string failed                |
|   B002   | SW_DISPLAY_ADDRESS_FAIL     | Address conversion to string failed                   |
|   B003   | SW_DISPLAY_AMOUNT_FAIL      | Amount conversion to string failed                    |
|   B005   | SW_TX_PARSING_FAIL          | Failed to parse raw transaction                       |
|   B006   | SW_TX_HASH_FAIL             | Failed to compute hash digest of raw transaction      |
|   B007   | SW_BAD_STATE                | Security issue with bad state                         |
|   B008   | SW_SIGNATURE_FAIL           | Signature of raw transaction failed                   |
|   9000   | OK                          | Success                                               |

## Extensible contract-call clear signing (descriptor V1)

`PROVIDE_CONTRACT_DESCRIPTOR` (`CLA=E0`, `INS=0B`, `P1=P2=0`) supplies a
signed operation description during a fresh `SIGN_TX` session, after the BIP32
path (`DATA_FIRST`) and before any transaction bytes. This is a QRL protocol;
it does not accept Ethereum's STORE/START_FLOW commands or JSON ABI. The
existing `SIGN_TX` streaming, transaction hash and ML-DSA-87 signature export
remain unchanged. Review begins at `DATA_LAST`.

The initial profile covers **all arguments, in order**, of a function with one
to three static 64-byte QRVM ABI words. Supported field types are QRL address
(`01`, full 64 bytes), uint256 (`02`, upper 32 bytes zero), and bool (`03`, first
63 bytes zero and last byte 0 or 1). Integers are displayed as exact unscaled
decimal values, never as token amounts. Arrays, dynamic offsets, strings,
structs, extra calldata, nonzero native value, contract creation and nonempty
access lists are outside V1. This is extensible across attested contract
functions within that profile, not arbitrary ABI decoding.

### Descriptor wire format

All integers in the signed body are big endian; strings are length-prefixed
ASCII without NUL terminators.

| Field | Bytes | Meaning |
| --- | --- | --- |
| Version | 1 | `01` |
| Chain ID | 32 | Nonzero complete Chain ID, left-padded with zeros |
| Contract | 64 | Nonzero QRL destination address |
| Selector | 4 | Exact function selector |
| Operation length, operation | 1 + 1..24 | Human-readable operation name |
| Field count | 1 | 1..3 |
| Fields, in ABI order | variable | Type byte, label length byte, label (1..12 bytes) |
| Issuer signature | 8..72 | Complete DER ECDSA P-256 signature |

Operation names and labels must begin with an ASCII letter and contain only
letters, digits, spaces, `_` and `-`, with no trailing space. A descriptor fits
in a single short APDU (maximum signed body 169 bytes, signature 72 bytes).
The issuer signs `SHA-256(ASCII("QRL-CONTRACT-DESCRIPTOR-V1") || body)`.

The issuer must attest the contract/network, selector, exact argument types,
order and actual meaning of every displayed name. A selector alone does not
establish semantics; collisions and upgradeable contracts require issuer
policy and descriptor maintenance. Device verification authenticates that
attestation; it does not inspect on-chain bytecode or contact a node. A wallet
must obtain signed descriptors, not hold the production issuer private key.
Descriptors have no expiry or on-chain freshness proof in V1.

On Nano the attested label and its value share the same font, separated by a
line break. Issuers must choose labels that remain unambiguous in this layout:
use a descriptive name such as `Limit`, rather than embedding a number or unit
suffix that could be mistaken for part of the value (for example `Limit 1`).

### Build configuration and failure behavior

`CONTRACT_DESCRIPTOR_PUBLIC_KEY=04<x><y>` configures the production issuer.
The build validates the P-256 point and rejects the publicly known test key.
No issuer is trusted by default. This authority is independent from
`TOKEN_METADATA_PUBLIC_KEY`; enabling token metadata does not enable contract
descriptors. A debug-only test issuer is available with
`DEBUG=1 CONTRACT_DESCRIPTOR_TEST_KEY=1` and the device displays
**TEST contract call**. Test credentials must never attest production contracts.

| Result | Status |
| --- | --- |
| Descriptor accepted for the current session | `9000` |
| Malformed or unsupported descriptor | `6A80` |
| Invalid issuer signature | `6982` |
| No contract descriptor issuer configured | `6A88` |
| Transaction/profile mismatch | `6A89` |
| Wrong P1/P2 | `6A86` |
| Wrong order, duplicate descriptor, or mixing token and contract metadata | `B007` |

Every descriptor error or mismatch aborts the session and revokes signature
export. A successfully authenticated descriptor that does not match the final
transaction is rejected even with blind signing enabled: no silent downgrade.
Descriptors cannot survive a new path, rejection, completed signature export,
or reset. Without a descriptor, ordinary native/token/blind-signing behavior
continues unchanged.

### Review and manual demonstration

The review shows From, native Amount (`QRL 0` for V1), To (actual contract),
Operation, all numbered arguments, Chain ID and fees, with optional nonce and
transaction hash. Numbered argument labels are distinct from device-generated
fields. On Nano, short `Arg 1`/`Arg 2`/`Arg 3` titles keep the entire attested
label inside the paginated value, avoiding title truncation. Approval and rejection use the ordinary transaction signing flow;
Nano also displays the explicit `Sign contract call` confirmation.

Build for Flex in the development container:

```sh
export BOLOS_SDK="$FLEX_SDK"
make clean
make -j4 DEBUG=1 CONTRACT_DESCRIPTOR_TEST_KEY=1
speculos --model flex --display headless --api-port 5003 --apdu-port 5004 build/flex/bin/app.elf
```

Run a clean build whenever changing issuer keys, test-key flags or DEBUG: the
SDK may otherwise reuse objects compiled with earlier settings.

With the emulator already running, use the tests virtual environment on the
host:

```sh
tests/venv/bin/python examples/contract_call.py --test-key --url http://127.0.0.1:5003
```

The example uses a synthetic contract, waits for device approval, verifies the
returned ML-DSA-87 signature and broadcasts nothing. Use the existing browser
touch frontend when working over SSH; the API port is not itself a device UI.
`--dry-run` builds the request without contacting the emulator. `--limit` and
`--disabled` change the example arguments. Real wallets fetch already signed
descriptors from an issuer; `--issuer-key` is only an issuer-side development
convenience.

Device tests: build with both `TOKEN_METADATA_TEST_KEY=1` and
`CONTRACT_DESCRIPTOR_TEST_KEY=1`, then run
`pytest tests --device flex --token-metadata-test-key --contract-descriptor-test-key`.
The default build rejects descriptors with `6A88`; issuer-dependent tests skip
unless `--contract-descriptor-test-key` requires them, in which case a missing
issuer fails the suite. CI runs both configurations.
