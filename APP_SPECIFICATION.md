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

#### Supported clear-signed call

Only `transfer(address,uint256)` is decoded in this version:

- Selector: `a9059cbb` (4 bytes).
- Recipient: one 64-byte QRVM ABI word.
- Amount: one 64-byte word, with the upper 32 bytes zero (`uint256`).
- Exact calldata length: 132 bytes; no additional bytes. The RLP parser retains
  the first 256 calldata bytes for operation decoders and records the full length;
  larger payloads continue to be streamed and hashed. This storage limit does not
  broaden the supported clear-signing profile.
- Token contract and full Chain ID must match the verified descriptor.
- Native QRL value must be zero; access list must be empty.

The screen shows the sending account, token amount/symbol, actual token
recipient, token contract, Chain ID, and maximum fees in QRL, plus optional nonce
and transaction hash. The signature covers the original complete transaction,
including calldata. Recognition does not simulate execution or guarantee a
successful transfer or the amount ultimately credited by a custom token.

Other calls, mismatching descriptors, noncanonical token arguments, native
value, or nonempty access lists follow the existing blind-signing policy; with
blind signing disabled they are rejected. `approve`, `transferFrom`, NFT calls,
routers, and general ABI decoding are outside this version's supported profile.

Descriptors exist only in RAM for one signing session. `DATA_FIRST`, address
requests, and aborted sessions invalidate them; none are persisted to NVM or
reused automatically. Signature chunks additionally require an approved session.

See `tests/application_client/token_metadata.py` for payload generation and
`examples/token_call.py` for an interactive Speculos example.

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
