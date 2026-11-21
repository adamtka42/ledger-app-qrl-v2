# QRL v2.0 Transaction Serialization

## Overview

The app signs QRL v2.0 dynamic-fee (EIP-1559-style, type `0x02`) transactions.
The host streams the **unsigned signing preimage** to the device; the device
hashes exactly the bytes it receives, displays the decoded fields for user
confirmation, and returns a detached ML-DSA-87 signature.

## Signing preimage

```text
preimage = 0x02 || rlp([chain_id, nonce, gas_tip_cap, gas_fee_cap, gas,
                        to, value, data, access_list, descriptor,
                        extra_params])
sighash  = Keccak-256(preimage)          // legacy Keccak, 32 bytes
```

The device signs the 32-byte `sighash` (it is not hashed again) with the
fixed 8-byte signing context `5a4f4e4401010000`
(`"ZOND" || version 0x01 || descriptor 01 00 00`). Signing is hedged.

## Fields

| # | Field | Constraint enforced by the device |
| ---: | --- | --- |
| 1 | `chain_id` | ≤ 32 bytes |
| 2 | `nonce` | ≤ 8 bytes |
| 3 | `gas_tip_cap` | ≤ 32 bytes (maxPriorityFeePerGas) |
| 4 | `gas_fee_cap` | ≤ 32 bytes (maxFeePerGas) |
| 5 | `gas` | ≤ 8 bytes |
| 6 | `to` | exactly 64 bytes, or empty (contract creation) |
| 7 | `value` | ≤ 32 bytes |
| 8 | `data` | opaque |
| 9 | `access_list` | opaque RLP item |
| 10 | `descriptor` | exactly `01 00 00` (ML-DSA-87) |
| 11 | `extra_params` | reserved; must be empty, but present in the signed list |

The list must contain exactly these 11 items; trailing or missing items fail
parsing. The transaction is parsed and hashed chunk by chunk as the APDUs
arrive (`src/tx_stream.c`), so there is no fixed size limit; only a sanity cap
of `TX_MAX_TOTAL_LEN` (64 KiB, `src/tx_types.h`) applies.

The recipient length is retained for review: an empty `to` is displayed as
`Operation: Create contract`, while a 64-byte all-zero `to` remains a recipient
address and is displayed under `To`. Non-empty `data` (including contract
initialization bytecode) or a non-empty access list still requires blind signing
to be enabled and the corresponding warning to be acknowledged.

The full on-chain transaction appends `signature` (4,627 bytes) and
`public_key` (2,592 bytes) after `extra_params`; the device never receives or
parses that signed envelope; assembling it is the host's job.

## NFT clear signing

Transfers and approvals of NFT collections are reviewed by name instead of
being blind-signed, provided the host first identifies the collection with
metadata signed by the token metadata issuer the firmware was built with.

After the first `SIGN_TX` command (the derivation path) and before any
transaction byte, the host sends `PROVIDE_NFT_METADATA` (`INS 0x0D`, `P1 = P2 = 0`):

```text
0x01 || chain_id (32 bytes, big-endian) || contract (64 bytes)
     || name_len (1 byte, 1..32) || name || DER ECDSA P-256 signature
signature over SHA-256("QRL-NFT-METADATA-V1" || everything before the signature)
```

The name is ASCII letters and digits, with single ` `, `.`, `-` or `_`
separators between them. The command answers `6A80` for a malformed payload,
`6982` for a signature the issuer did not make, `6A88` when the build has no
issuer, and `B007` outside that point of a signing session. Token metadata, NFT
metadata and a contract descriptor are mutually exclusive within one transaction.

The transaction is then clear-signed only if it is sent to that contract on
that chain, carries no value and no access list, and its calldata is exactly
one of the calls below, with canonical 64-byte argument words:

| Call | Review |
| --- | --- |
| `transferFrom(address,address,uint256)` | Send NFT: To, Collection, NFT contract, Token ID |
| `safeTransferFrom(address,address,uint256)` | same |
| `safeTransferFrom(address,address,uint256,bytes)` | same; `bytes` must be empty |
| `safeTransferFrom(address,address,uint256,uint256,bytes)` | same, plus a non-zero Quantity; `bytes` must be empty |
| `approve(address,uint256)` | Approve NFT: Spender, Token ID. A zero spender is shown as a revocation |
| `setApprovalForAll(address,bool)` | Approve or revoke an Operator for the entire collection |

When the `from` argument of a transfer is not the signing account, it is shown
as `NFT owner`. Anything else sent to the collection, including a transfer with
attached data or a batch transfer, is not described by the metadata and falls
back to the blind-signing rules above.

## Signature

ML-DSA-87 (FIPS 204): 4,627-byte detached signature, returned to the host in
chunks (see `APP_SPECIFICATION.md`). The device verifies its own signature
before releasing it.

## See also

- `APP_SPECIFICATION.md`: APDU interface
- The QRL-Ledger-v1 wallet profile in the QRL v2.0 specifications
  repository (derivation, addresses, signing context)
