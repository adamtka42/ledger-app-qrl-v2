# Technical Specification

## About

This documentation describes the APDU messages interface to communicate with the QRL v2.0 application.

The application covers the following functionalities :

- Get a public QRL v2.0 address given a BIP 32 path
- Sign a QRL v2.0 transaction given a BIP 32 path and RLP encoded transaction data
- Sign a readable personal message using the QRL signed-message format
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

### SIGN PERSONAL MESSAGE

`CLA=E0`, `INS=08` signs a reviewed QRL personal message using ML-DSA-87.
It is separate from transaction signing and does not require blind signing.

1. `P1=00, P2=00`: BIP32 path in the same format as SIGN_TX, followed by the
   unsigned 4-byte big-endian message length. No text in this first command.
2. `P1=01, P2=00`: nonempty intermediate text chunks (up to 255 bytes).
3. `P1=02, P2=00`: the final text chunk. For an empty message send an empty
   final chunk. The device reviews only after exactly the declared length arrives.
4. After user approval the response contains signature chunk 0. Retrieve chunks
   1 through 17 with `P1=02, P2=01..11` (hex), with empty command data, using
   **INS=08**, not SIGN_TX. The complete signature is 4627 bytes.

Version 1 supports up to 1024 raw bytes of printable ASCII (`20..7E`) and at
most 32 LF bytes (`0A`). Non-ASCII UTF-8, NUL, tabs, CR and other controls are
rejected with `6A80`; there is no binary or hash-only signing fallback. Bytes
are neither normalized nor interpreted as hexadecimal text. The empty message
has a labeled empty preview and length zero. Existing app BIP32 policy applies.

The signed digest is the format used by go-qrl `accounts.TextHash` and
web3-qrl-accounts `hashMessage`:

```
Keccak256(0x19 || ASCII("QRL Signed Message:\n") || ASCII(decimal_byte_length) || raw_message)
```

The prefix includes a real LF after the colon, with no NUL or delimiter after
the decimal length. ML-DSA uses the existing 8-byte context
`5a4f4e4401010000` (`ZOND`, context version 1, descriptor `010000`). Neither
Ethereum's prefix, a raw message hash, nor a host-supplied digest is accepted.
For hex-looking text, pass its encoded bytes to web3's `hashMessage` to avoid
that API's automatic hex decoding. For example literal ASCII `0x1234` should
be checked with `hashMessage("0x307831323334")`.

Review shows the derived account, exact byte count and the complete message.
Nano S+/X receive one Message value and use NBGL's built-in pagination. Stax and
Flex receive numbered fragments sized with NBGL font and layout metrics, with
word wrapping. Each fragment fits a normal review page without an optional More
view. Spaces and LF bytes are preserved across fragment boundaries. The final
action is Sign message on all four models.
Text is erased after approval, rejection or abort. Fetching a signature requires
the approved message session; new messages, transaction starts and address
derivation invalidate previous exports. Wrong lengths/oversize return `6A87`,
wrong parameters `6A86`, wrong session `B007`, user rejection `6985`.

Manual Speculos example (no blockchain connection):

```sh
tests/venv/bin/python examples/personal_message.py --url http://127.0.0.1:5003
```

Use `--message`, `--message-file`, `--dry-run`, or `--output /tmp/message.json`.
The JSON output contains public verification data only. Wallets must integrate
this APDU sequence and verify signatures against the QRL message digest.

## Status Words

The following standard Status Words are returned for all APDUs.

| SW       | SW name                     | Description                                           |
| ---      | ---                         | ---                                                   |
|   6985   | SW_DENY                     | Rejected by user                                      |
|   6A80   | SW_MESSAGE_INVALID          | Personal message contains unsupported text            |
|   6A86   | SW_WRONG_P1P2               | Either P1 or P2 is incorrect                          |
|   6A87   | SW_WRONG_DATA_LENGTH        | Lc or minimum APDU length is incorrect                |
|   6D00   | SW_INS_NOT_SUPPORTED        | No command exists with INS                            |
|   6E00   | SW_CLA_NOT_SUPPORTED        | Bad CLA used for this application                     |
|   B000   | SW_WRONG_RESPONSE_LENGTH    | Wrong response length (buffer size problem)           |
|   B001   | SW_DISPLAY_BIP32_PATH_FAIL  | BIP32 path conversion to string failed                |
|   B002   | SW_DISPLAY_ADDRESS_FAIL     | Address conversion to string failed                   |
|   B003   | SW_DISPLAY_AMOUNT_FAIL      | Amount conversion to string failed                    |
|   B005   | SW_TX_PARSING_FAIL          | Failed to parse raw transaction                       |
|   B006   | SW_TX_HASH_FAIL             | Failed to compute hash digest of raw transaction      |
|   B007   | SW_BAD_STATE                | Security issue with bad state                         |
|   B008   | SW_SIGNATURE_FAIL           | Transaction or personal-message signing failed        |
|   9000   | OK                          | Success                                               |
