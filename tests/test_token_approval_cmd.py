"""Clear signing for SQRCTF1 approve(address,uint256), with blind signing off."""

import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.token_metadata import approval_calldata, make_test_metadata
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks
from application_client.token_calls import PATH, preimage, enable_nonce_and_hash


MAX_ALLOWANCE = 2**256 - 1


def approval_confirmation_text(device, amount):
    if not device.is_nano:
        return None  # Touch devices confirm with their Hold to sign control.
    if amount == MAX_ALLOWANCE:
        return r"^Approve unlimited"
    if amount == 0:
        return r"^Revoke token"
    return r"^Approve token"


@pytest.mark.parametrize("amount,case,decision", [
    (25_000_000, "limited", "approve"),
    (0, "revoke", "approve"),
    (MAX_ALLOWANCE, "unlimited", "approve"),
    (MAX_ALLOWANCE - 1, "large_limited", "approve"),
    (MAX_ALLOWANCE, "unlimited", "reject"),
])
def test_clear_sign_token_approval(backend, token_issuer, device, scenario_navigator, amount, case, decision):
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    tx = preimage(approval_calldata(amount))
    name = f"test_token_approval_{case}_{decision}"
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
        scenario_navigator.review_approve(test_name=name,
                                          custom_screen_text=approval_confirmation_text(device, amount))
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    for changed in (approval_calldata((amount + 1) % 2**256),
                    approval_calldata(amount, spender=b"\x33" * 64)):
        digest = keccak.new(digest_bits=256, data=preimage(changed)).digest()
        assert not ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)


def test_token_approval_without_metadata_needs_blind_signing(backend):
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(approval_calldata(25_000_000))):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("mutation", [
    "contract", "chain", "high_chain", "selector", "padding", "short", "trailing",
    "value", "access_list", "creation", "zero_spender",
])
def test_unsupported_token_approval_needs_blind_signing(backend, token_issuer, mutation):
    kwargs = {}
    data = bytearray(approval_calldata(25_000_000))
    if mutation == "contract": kwargs["contract"] = b"\x33" * 64
    elif mutation == "chain": kwargs["chain_id"] = 2
    elif mutation == "high_chain": kwargs["chain_id"] = 2**128 + 1
    elif mutation == "selector": data[0] ^= 1
    elif mutation == "padding": data[68] = 1
    elif mutation == "short": data = data[:-1]
    elif mutation == "trailing": data += b"\0"
    elif mutation == "value": kwargs["value"] = 1
    elif mutation == "access_list": kwargs["access_list"] = b"\xc1\x80"
    elif mutation == "creation": kwargs["contract"] = b""
    elif mutation == "zero_spender": data[4:68] = bytes(64)
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(bytes(data), **kwargs), token_metadata=make_test_metadata()):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_token_approval_with_nonce_and_hash(backend, token_issuer, device, navigator, scenario_navigator):
    enable_nonce_and_hash(backend, device, navigator)
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    tx = preimage(approval_calldata(MAX_ALLOWANCE))
    with client.sign_tx(PATH, tx, token_metadata=make_test_metadata(symbol="LONGTOKEN123")):
        scenario_navigator.review_approve(
            custom_screen_text=approval_confirmation_text(device, MAX_ALLOWANCE))
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
