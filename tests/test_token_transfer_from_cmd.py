"""Fungible transferFrom clear signing, with blind signing disabled by default."""

import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.token_calls import PATH, preimage, enable_nonce_and_hash
from application_client.token_metadata import make_test_metadata, transfer_from_calldata
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks


OWNER = b"\x33" * 64
RECIPIENT = b"\x11" * 64


@pytest.mark.parametrize("amount,same_owner,decision,case", [
    (10_000_000, False, "approve", "operator"),
    (10_000_000, True, "approve", "self"),
    (0, False, "approve", "zero"),
    (2**256 - 1, False, "approve", "maximum"),
    (10_000_000, False, "reject", "reject"),
])
def test_clear_sign_token_transfer_from(backend, token_issuer, scenario_navigator,
                                        amount, same_owner, decision, case):
    client = BoilerplateCommandSender(backend)
    signing_address = client.get_public_key(PATH).data[1:]
    assert len(signing_address) == 64
    public_key = get_public_key_chunks(backend)
    owner = signing_address if same_owner else OWNER
    tx = preimage(transfer_from_calldata(amount, owner, RECIPIENT))
    name = f"test_token_transfer_from_{case}"
    if decision == "reject":
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_tx(PATH, tx, token_metadata=make_test_metadata()):
                scenario_navigator.review_reject(test_name=name)
        assert exc.value.status == Errors.SW_DENY
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
        assert exc.value.status == Errors.SW_BAD_STATE
        return

    with client.sign_tx(PATH, tx, token_metadata=make_test_metadata()):
        scenario_navigator.review_approve(test_name=name)
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    # All three arguments, including the owner distinct from the signer, are bound.
    for changed in (transfer_from_calldata(amount, b"\x44" * 64, RECIPIENT),
                    transfer_from_calldata(amount, owner, b"\x55" * 64),
                    transfer_from_calldata((amount + 1) % 2**256, owner, RECIPIENT)):
        digest = keccak.new(digest_bits=256, data=preimage(changed)).digest()
        assert not ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)


def test_token_transfer_from_without_metadata_needs_blind_signing(backend):
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(transfer_from_calldata(10_000_000, OWNER))):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("mutation", [
    "contract", "chain", "high_chain", "selector", "padding", "short", "trailing",
    "two_words", "value", "access_list", "creation",
])
def test_unsupported_transfer_from_needs_blind_signing(backend, token_issuer, mutation):
    kwargs = {}
    data = bytearray(transfer_from_calldata(10_000_000, OWNER))
    if mutation == "contract": kwargs["contract"] = b"\x44" * 64
    elif mutation == "chain": kwargs["chain_id"] = 2
    elif mutation == "high_chain": kwargs["chain_id"] = 2**128 + 1
    elif mutation == "selector": data[0] ^= 1
    elif mutation == "padding": data[132] = 1
    elif mutation == "short": data = data[:-1]
    elif mutation == "trailing": data += b"\0"
    elif mutation == "two_words": data = data[:132]
    elif mutation == "value": kwargs["value"] = 1
    elif mutation == "access_list": kwargs["access_list"] = b"\xc1\x80"
    elif mutation == "creation": kwargs["contract"] = b""
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(bytes(data), **kwargs), token_metadata=make_test_metadata()):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_token_transfer_from_with_nonce_and_hash(backend, token_issuer, device, navigator, scenario_navigator):
    enable_nonce_and_hash(backend, device, navigator)
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    tx = preimage(transfer_from_calldata(10_000_000, OWNER))
    with client.sign_tx(PATH, tx, token_metadata=make_test_metadata(symbol="LONGTOKEN123")):
        scenario_navigator.review_approve()
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
