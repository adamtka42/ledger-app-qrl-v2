"""Clear signing for NFT transfers and approvals, with blind signing off."""

import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.contract_calls import make_test_descriptor
from application_client.nft_metadata import (
    TEST_COLLECTION, TEST_OWNER, approve_all_calldata, make_test_nft_metadata,
    multi_transfer_calldata, nft_approve_calldata, nft_metadata_body,
    safe_transfer_data_calldata, sign_test_body, transfer_from_calldata)
from application_client.token_metadata import make_test_metadata, transfer_calldata
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks
from application_client.token_calls import PATH, preimage, start, enable_nonce_and_hash

MAX_TOKEN_ID = 2**256 - 1
ZERO_ADDRESS = bytes(64)


def provide(backend, payload, *, p1=0, p2=0):
    return backend.exchange(cla=CLA, ins=InsType.PROVIDE_NFT_METADATA, p1=p1, p2=p2, data=payload)


def signer_address(client):
    """The device answers with "Q" followed by the 64-byte address."""
    response = client.get_public_key(PATH).data
    assert len(response) == 65 and response[:1] == b"Q"
    return response[1:]


# Confirmation page titles, as shown on Nano; touch devices use Hold to sign.
SEND, APPROVE, REVOKE, APPROVE_ALL, REVOKE_ALL = (
    r"^Send NFT", r"^Approve NFT", r"^Revoke NFT", r"^Approve entire", r"^Revoke NFT")

# name -> (calldata builder taking the signer address, confirmation title)
CALLS = {
    "transfer": (lambda me: transfer_from_calldata(42, owner=me), SEND),
    "safe_transfer": (lambda me: transfer_from_calldata(42, owner=me, safe=True), SEND),
    "safe_transfer_data": (lambda me: safe_transfer_data_calldata(MAX_TOKEN_ID, owner=me), SEND),
    "operator_transfer": (lambda me: transfer_from_calldata(42, owner=TEST_OWNER), SEND),
    "multi_transfer": (lambda me: multi_transfer_calldata(7, 250, owner=me), SEND),
    "approve": (lambda me: nft_approve_calldata(42), APPROVE),
    "revoke": (lambda me: nft_approve_calldata(42, spender=ZERO_ADDRESS), REVOKE),
    "approve_all": (lambda me: approve_all_calldata(True), APPROVE_ALL),
    "revoke_all": (lambda me: approve_all_calldata(False), REVOKE_ALL),
}


def approve_and_verify(backend, client, device, scenario_navigator, tx, confirmation,
                       test_name=None, **kwargs):
    public_key = get_public_key_chunks(backend)
    with client.sign_tx(PATH, tx, nft_metadata=make_test_nft_metadata(**kwargs)):
        scenario_navigator.review_approve(
            test_name=test_name, custom_screen_text=confirmation if device.is_nano else None)
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    return public_key, signature


@pytest.mark.parametrize("case", list(CALLS))
def test_clear_sign_nft(backend, nft_issuer, device, scenario_navigator, case):
    client = BoilerplateCommandSender(backend)
    build, confirmation = CALLS[case]
    data = build(signer_address(client))
    public_key, signature = approve_and_verify(backend, client, device, scenario_navigator,
                                               preimage(data), confirmation,
                                               test_name=f"test_nft_{case}")
    # The signature covers every argument that was reviewed.
    changed = bytearray(data)
    changed[-1] ^= 1
    digest = keccak.new(digest_bits=256, data=preimage(bytes(changed))).digest()
    assert not ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)


def test_nft_transfer_refused(backend, nft_issuer, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    tx = preimage(transfer_from_calldata(42, owner=signer_address(client)))
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, tx, nft_metadata=make_test_nft_metadata()):
            scenario_navigator.review_reject(test_name="test_nft_transfer_refused")
    assert exc.value.status == Errors.SW_DENY
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


def test_nft_review_with_nonce_and_hash(backend, nft_issuer, device, navigator, scenario_navigator):
    """Largest review: operator transfer of a multi-token ID with the longest name and values."""
    enable_nonce_and_hash(backend, device, navigator)
    client = BoilerplateCommandSender(backend)
    signer_address(client)  # derive the key that the signature is verified against
    name = "Quantum Resistant Collectibles 1"
    tx = preimage(multi_transfer_calldata(MAX_TOKEN_ID, MAX_TOKEN_ID), chain_id=1337)
    approve_and_verify(backend, client, device, scenario_navigator, tx, SEND,
                       chain_id=1337, name=name)


def test_nft_call_without_metadata_needs_blind_signing(backend):
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(transfer_from_calldata(42))):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("mutation", [
    "contract", "chain", "high_chain", "selector", "token_transfer", "padding", "short", "trailing",
    "value", "access_list", "creation",
])
def test_unsupported_nft_call_needs_blind_signing(backend, nft_issuer, mutation):
    kwargs = {}
    data = bytearray(transfer_from_calldata(42))
    if mutation == "contract": kwargs["contract"] = b"\x33" * 64
    elif mutation == "chain": kwargs["chain_id"] = 2
    elif mutation == "high_chain": kwargs["chain_id"] = 2**128 + 1
    elif mutation == "selector": data[0] ^= 1
    elif mutation == "token_transfer": data = bytearray(transfer_calldata(42))
    elif mutation == "padding": data[4 + 2 * 64] = 1
    elif mutation == "short": data = data[:-1]
    elif mutation == "trailing": data += b"\0"
    elif mutation == "value": kwargs["value"] = 1
    elif mutation == "access_list": kwargs["access_list"] = b"\xc1\x80"
    elif mutation == "creation": kwargs["contract"] = b""
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(bytes(data), **kwargs), nft_metadata=make_test_nft_metadata()):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("data", [
    safe_transfer_data_calldata(42, data=b"\x01"),
    multi_transfer_calldata(7, 1, data=b"hello"),
    multi_transfer_calldata(7, 0),
    approve_all_calldata(True, operator=ZERO_ADDRESS),
], ids=["attached_data", "multi_attached_data", "zero_quantity", "zero_operator"])
def test_ambiguous_nft_call_needs_blind_signing(backend, nft_issuer, data):
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(data), nft_metadata=make_test_nft_metadata()):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_nft_metadata_wrong_issuer_aborts_session(backend, request):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_nft_metadata(scalar=2))
    if request.config.getoption("--token-metadata-test-key"):
        assert exc.value.status == Errors.SW_TOKEN_METADATA_UNTRUSTED
    else:
        assert exc.value.status in (Errors.SW_TOKEN_METADATA_UNTRUSTED, Errors.SW_TOKEN_METADATA_NO_ISSUER)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=0, data=preimage())
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("mutation", ["signature", "contract", "chain", "name", "token_domain", "no_domain"])
def test_nft_metadata_tampering(backend, nft_issuer, mutation):
    start(backend)
    payload = bytearray(make_test_nft_metadata())
    index = {"signature": -1, "contract": 33, "chain": 31, "name": 99}
    if mutation.endswith("domain"):
        # A signature made for another kind of metadata, or for none, is not accepted.
        body = nft_metadata_body(1, TEST_COLLECTION, "Quantum Cats")
        domain = b"QRL-TOKEN-METADATA-V1" if mutation == "token_domain" else b""
        payload = body + sign_test_body(body, domain=domain)
    else:
        payload[index[mutation]] ^= 1
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, bytes(payload))
    assert exc.value.status == Errors.SW_TOKEN_METADATA_UNTRUSTED


def unchecked_metadata(name: bytes) -> bytes:
    body = b"\x01" + (1).to_bytes(32, "big") + TEST_COLLECTION + bytes([len(name)]) + name
    return body + sign_test_body(body)


@pytest.mark.parametrize("payload", [
    b"", b"\x01", make_test_nft_metadata() + b"\0",
    unchecked_metadata(b"Cats\nTo"), unchecked_metadata(b" Cats"), unchecked_metadata(b"Cats  2"),
    unchecked_metadata(b"C" * 33),
], ids=["empty", "version_only", "trailing", "newline", "leading_space", "double_space", "long"])
def test_nft_metadata_invalid(backend, payload):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, payload)
    assert exc.value.status == Errors.SW_TOKEN_METADATA_INVALID


def test_nft_metadata_wrong_p1p2(backend):
    for p1, p2 in ((1, 0), (0, 1)):
        start(backend)
        with pytest.raises(ExceptionRAPDU) as exc:
            provide(backend, make_test_nft_metadata(), p1=p1, p2=p2)
        assert exc.value.status == Errors.SW_WRONG_P1P2


def test_nft_metadata_requires_fresh_receiving_session(backend, nft_issuer):
    start(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0, data=b"\x02")
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_nft_metadata())
    assert exc.value.status == Errors.SW_BAD_STATE


def test_nft_metadata_does_not_survive_new_session(backend, nft_issuer):
    start(backend)
    provide(backend, make_test_nft_metadata())
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(transfer_from_calldata(42))):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("first", ["token", "nft", "contract"])
def test_one_kind_of_metadata_per_transaction(backend, nft_issuer, token_issuer, contract_issuer, first):
    """A contract cannot be described both as a collection and as something else."""
    payloads = {
        "token": (InsType.PROVIDE_TOKEN_METADATA, make_test_metadata()),
        "nft": (InsType.PROVIDE_NFT_METADATA, make_test_nft_metadata()),
        "contract": (InsType.PROVIDE_CONTRACT_DESCRIPTOR, make_test_descriptor()),
    }
    for second in payloads:
        if second == first or "nft" not in (first, second):
            continue
        start(backend)
        backend.exchange(cla=CLA, ins=payloads[first][0], p1=0, p2=0, data=payloads[first][1])
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=payloads[second][0], p1=0, p2=0, data=payloads[second][1])
        assert exc.value.status == Errors.SW_BAD_STATE
