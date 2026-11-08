import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.token_metadata import TEST_CONTRACT, make_test_metadata, transfer_calldata
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks
from application_client.token_calls import PATH, preimage, start, provide, enable_nonce_and_hash


def test_token_metadata_wrong_issuer_aborts_session(backend, request):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_metadata(scalar=2))
    if request.config.getoption("--token-metadata-test-key"):
        assert exc.value.status == Errors.SW_TOKEN_METADATA_UNTRUSTED
    else:
        assert exc.value.status in (Errors.SW_TOKEN_METADATA_UNTRUSTED, Errors.SW_TOKEN_METADATA_NO_ISSUER)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=0, data=preimage())
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("mutation", ["signature", "contract", "chain", "symbol", "decimals", "domain"])
def test_token_metadata_tampering(backend, token_issuer, mutation):
    start(backend)
    payload = bytearray(make_test_metadata())
    index = {"signature": -1, "contract": 33, "chain": 31, "symbol": 99, "decimals": 97}
    if mutation == "domain":
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
        from application_client.token_metadata import metadata_body
        body = metadata_body(1, TEST_CONTRACT, "TKN", 6)
        payload = body + DSS.new(ECC.construct(curve="P-256", d=1), "deterministic-rfc6979",
                                  encoding="der").sign(SHA256.new(body))
    else:
        payload[index[mutation]] ^= 1
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, bytes(payload))
    assert exc.value.status == Errors.SW_TOKEN_METADATA_UNTRUSTED


@pytest.mark.parametrize("payload", [b"", b"\x01", make_test_metadata() + b"\0"])
def test_token_metadata_bad_length(backend, payload):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, payload)
    assert exc.value.status == Errors.SW_TOKEN_METADATA_INVALID


@pytest.mark.parametrize("symbol", ["QRL", "qrl", "Qrl"])
def test_token_metadata_native_symbol_rejected(backend, symbol):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_metadata(symbol=symbol))
    assert exc.value.status == Errors.SW_TOKEN_METADATA_INVALID


def test_token_metadata_requires_fresh_receiving_session(backend, token_issuer):
    start(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0, data=b"\x02")
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_metadata())
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("mutation", ["contract", "chain", "high_chain", "selector", "padding", "short", "trailing", "value", "access_list", "creation"])
def test_unsupported_token_call_needs_blind_signing(backend, token_issuer, mutation):
    kwargs = {}
    data = bytearray(transfer_calldata(10_000_000))
    if mutation == "contract": kwargs["contract"] = bytes.fromhex("33" * 64)
    elif mutation == "chain": kwargs["chain_id"] = 2
    elif mutation == "high_chain": kwargs["chain_id"] = 2**128 + 1
    elif mutation == "selector": data[0] ^= 1
    elif mutation == "padding": data[68] = 1
    elif mutation == "short": data = data[:-1]
    elif mutation == "trailing": data += b"\0"
    elif mutation == "value": kwargs["value"] = 1
    elif mutation == "access_list": kwargs["access_list"] = b"\xc1\x80"
    elif mutation == "creation": kwargs["contract"] = b""
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage(bytes(data), **kwargs), token_metadata=make_test_metadata()):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_token_metadata_does_not_survive_new_session(backend, token_issuer):
    start(backend)
    provide(backend, make_test_metadata())
    client = BoilerplateCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, preimage()):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_clear_sign_token_transfer(backend, token_issuer, scenario_navigator, decision):
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    tx = preimage()
    if decision == "reject":
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_tx(PATH, tx, token_metadata=make_test_metadata()):
                scenario_navigator.review_reject(test_name="test_clear_sign_token_transfer_reject")
        assert exc.value.status == Errors.SW_DENY
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
        assert exc.value.status == Errors.SW_BAD_STATE
        return
    with client.sign_tx(PATH, tx, token_metadata=make_test_metadata()):
        scenario_navigator.review_approve(test_name="test_clear_sign_token_transfer_approve")
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    tampered = keccak.new(digest_bits=256, data=preimage(transfer_calldata(20_000_000))).digest()
    assert not ML_DSA_87.verify(public_key, tampered, signature, ctx=SIGNING_CONTEXT)


def test_token_review_with_nonce_and_hash(backend, token_issuer, device, navigator, scenario_navigator):
    enable_nonce_and_hash(backend, device, navigator)
    client = BoilerplateCommandSender(backend)
    tx = preimage()
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    with client.sign_tx(PATH, tx, token_metadata=make_test_metadata()):
        scenario_navigator.review_approve()
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
