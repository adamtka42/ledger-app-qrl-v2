"""Authenticated, extensible clear review of static contract arguments."""
import pytest
import re
from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.contract_calls import (
    TEST_CONTRACT, SELECTOR, FieldKind, encode_calldata,
    example_calldata, make_test_descriptor,
)
from application_client.token_calls import PATH, preimage, start, provide, enable_nonce_and_hash
from application_client.token_metadata import make_test_metadata
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks


def provide_descriptor(backend, payload=None, **kwargs):
    return backend.exchange(cla=CLA, ins=InsType.PROVIDE_CONTRACT_DESCRIPTOR,
                            p1=kwargs.get("p1", 0), p2=kwargs.get("p2", 0),
                            data=make_test_descriptor() if payload is None else payload)


def assert_revoked(backend):
    for p2 in (0, 1):
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=p2,
                             data=b"\x02" if p2 == 0 else b"")
        assert exc.value.status == Errors.SW_BAD_STATE


def test_contract_wrong_issuer(backend, request):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide_descriptor(backend, make_test_descriptor(scalar=2))
    expected = (Errors.SW_CONTRACT_DESCRIPTOR_UNTRUSTED,)
    if not request.config.getoption("--contract-descriptor-test-key"):
        expected += (Errors.SW_CONTRACT_DESCRIPTOR_NO_ISSUER,)
    assert exc.value.status in expected
    assert_revoked(backend)


@pytest.mark.parametrize("case", ["approve", "reject", "maximum", "false", "single"])
def test_contract_call_review(backend, contract_issuer, device, navigator, scenario_navigator, case):
    if case == "maximum":
        enable_nonce_and_hash(backend, device, navigator)
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    fields = ((FieldKind.UINT256, "Integer"),)
    descriptor = make_test_descriptor(fields=fields) if case == "single" else make_test_descriptor()
    if case == "maximum":
        descriptor = make_test_descriptor(operation="ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:24],
                                          fields=((1, "AddressField"), (2, "IntegerField"), (3, "BooleanField")))
    data = encode_calldata(SELECTOR, fields, (2**256 - 1,)) if case == "single" else example_calldata(
        limit=2**256 - 1 if case == "maximum" else 100, enabled=case != "false")
    tx = preimage(data, contract=TEST_CONTRACT)
    name = f"test_contract_call_{case}"
    if case == "reject":
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_tx(PATH, tx, contract_descriptor=descriptor):
                scenario_navigator.review_reject(test_name=name)
        assert exc.value.status == Errors.SW_DENY
        assert_revoked(backend)
        return
    with client.sign_tx(PATH, tx, contract_descriptor=descriptor):
        scenario_navigator.review_approve(test_name=name,
                                          custom_screen_text="Sign contract call" if device.is_nano else None)
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    # The signature covers every argument, the target, value and fees, not the description.
    for changed in (preimage(example_calldata(limit=101), contract=TEST_CONTRACT),
                    preimage(data, contract=b"\x55" * 64), preimage(data, contract=TEST_CONTRACT, value=1)):
        assert not ML_DSA_87.verify(public_key, keccak.new(digest_bits=256, data=changed).digest(),
                                    signature, ctx=SIGNING_CONTEXT)
    # All export chunks consumed: neither signature nor descriptor may be reused.
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(PATH, tx):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("mutation", [
    "chain", "high_chain", "contract", "selector", "short", "trailing", "huge",
    "integer_padding", "bool_padding", "bool_two", "access_list", "value", "creation",
])
def test_contract_mismatch_aborts(backend, contract_issuer, mutation):
    data = bytearray(example_calldata())
    kwargs = {"contract": TEST_CONTRACT}
    if mutation == "chain": kwargs["chain_id"] = 2
    elif mutation == "high_chain": kwargs["chain_id"] = 2**128 + 1
    elif mutation == "contract": kwargs["contract"] = b"\x55" * 64
    elif mutation == "selector": data[0] ^= 1
    elif mutation == "short": data = data[:-1]
    elif mutation == "trailing": data += b"\0"
    elif mutation == "huge": data += bytes(500)
    elif mutation == "integer_padding": data[68] = 1
    elif mutation == "bool_padding": data[132] = 1
    elif mutation == "bool_two": data[195] = 2
    elif mutation == "access_list": kwargs["access_list"] = b"\xc1\x80"
    elif mutation == "value": kwargs["value"] = 1
    elif mutation == "creation": kwargs["contract"] = b""
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(
                PATH, preimage(bytes(data), **kwargs), contract_descriptor=make_test_descriptor()):
            pass
    assert exc.value.status == Errors.SW_CONTRACT_CALL_MISMATCH
    assert_revoked(backend)


@pytest.mark.parametrize("mutation", ["signature", "chain", "contract", "selector", "operation", "label", "kind"])
def test_contract_descriptor_tampering(backend, contract_issuer, mutation):
    start(backend)
    payload = bytearray(make_test_descriptor())
    # Change to another structurally valid descriptor without updating its signature.
    positions = {"signature": -1, "chain": 31, "contract": 33, "selector": 97,
                 "operation": 102, "kind": 120, "label": 122}
    index = positions[mutation]
    payload[index] = 2 if mutation == "kind" else payload[index] ^ 1
    with pytest.raises(ExceptionRAPDU) as exc:
        provide_descriptor(backend, bytes(payload))
    assert exc.value.status == Errors.SW_CONTRACT_DESCRIPTOR_UNTRUSTED
    assert_revoked(backend)


@pytest.mark.parametrize("payload", [b"", b"\x01", make_test_descriptor() + b"\0"])
def test_contract_descriptor_bad_length(backend, payload):
    start(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        provide_descriptor(backend, payload)
    assert exc.value.status == Errors.SW_CONTRACT_DESCRIPTOR_INVALID
    assert_revoked(backend)


@pytest.mark.parametrize("case", ["no_session", "p1", "p2", "after_bytes", "twice", "token_then_contract", "contract_then_token"])
def test_contract_descriptor_session_order(backend, contract_issuer, request, case):
    if case in ("token_then_contract", "contract_then_token"):
        request.getfixturevalue("token_issuer")
    if case != "no_session":
        start(backend)
    else:
        # GET_PUBLIC_KEY invalidates the fixture's receiving session.
        BoilerplateCommandSender(backend).get_public_key(PATH)
    if case == "after_bytes":
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0, data=b"\x02")
    elif case == "twice" or case == "contract_then_token":
        provide_descriptor(backend)
    elif case == "token_then_contract":
        provide(backend, make_test_metadata())
    with pytest.raises(ExceptionRAPDU) as exc:
        if case == "contract_then_token":
            provide(backend, make_test_metadata())
        else:
            provide_descriptor(backend, p1=int(case == "p1"), p2=int(case == "p2"))
    assert exc.value.status == (Errors.SW_WRONG_P1P2 if case in ("p1", "p2") else Errors.SW_BAD_STATE)
    assert_revoked(backend)


def test_contract_descriptor_does_not_survive_new_session(backend, contract_issuer):
    start(backend)
    provide_descriptor(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(PATH, preimage(example_calldata(), contract=TEST_CONTRACT)):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("domain", [b"", b"QRL-TOKEN-METADATA-V1"])
def test_contract_descriptor_domain_binding(backend, contract_issuer, domain):
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS
    from application_client.contract_calls import descriptor_body
    start(backend)
    body = descriptor_body()
    signature = DSS.new(ECC.construct(curve="P-256", d=1), "deterministic-rfc6979",
                         encoding="der").sign(SHA256.new(domain + body))
    with pytest.raises(ExceptionRAPDU) as exc:
        provide_descriptor(backend, body + signature)
    assert exc.value.status == Errors.SW_CONTRACT_DESCRIPTOR_UNTRUSTED
    assert_revoked(backend)


@pytest.mark.parametrize("kind,label,value", [
    (FieldKind.ADDRESS, "WWWWWWWWWWWW", b"\x11" * 64),
    (FieldKind.UINT256, "Max integer", 2**256 - 1),
    (FieldKind.BOOL, "From", 0),
])
def test_contract_rendered_argument(backend, contract_issuer, device, scenario_navigator,
                                    monkeypatch, kind, label, value):
    fields = ((kind, label),)
    tx = preimage(encode_calldata(SELECTOR, fields, (value,)), contract=TEST_CONTRACT)
    descriptor = make_test_descriptor(fields=fields)
    pages = {}
    compare_text = backend.compare_screen_with_text
    title = "Arg 1" if device.is_nano else f"1. {label}"

    def capture(pattern):
        texts = [event.get("text", "") for event in backend.get_current_screen_content()["events"]]
        assert "More" not in texts
        for index, text in enumerate(texts):
            if re.fullmatch(re.escape(title) + r"(?: \(\d+/\d+\))?", text):
                # This is the only argument and the last row of its display section.
                # Nano shows one field per page; touch may group following fee fields.
                following = []
                for entry in texts[index + 1:]:
                    if entry in ("Chain ID", "Reject") or re.fullmatch(r"\d+ of \d+", entry):
                        break
                    following.append(entry)
                pages[text] = "".join(following)
        return compare_text(pattern)

    monkeypatch.setattr(backend, "compare_screen_with_text", capture)
    with BoilerplateCommandSender(backend).sign_tx(PATH, tx, contract_descriptor=descriptor):
        scenario_navigator.review_approve(do_comparison=False,
                                          custom_screen_text="Sign contract call" if device.is_nano else None)
    displayed = "".join(pages.values()).replace("\n", "")
    if kind == FieldKind.ADDRESS:
        expected = "Q" + value.hex()
    elif kind == FieldKind.BOOL:
        expected = "true" if value else "false"
    else:
        expected = str(value)
    assert displayed == (label if device.is_nano else "") + expected


def test_contract_mismatch_never_downgrades_to_blind_signing(backend, contract_issuer, device, navigator):
    from ragger.navigator import NavIns, NavInsID
    if device.is_nano:
        for text in ("App settings", "Blind signing", "Back"):
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], text=text,
                                           screen_change_before_first_instruction=False)
    else:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS, NavIns(NavInsID.TOUCH, (200, 113)),
                            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                           screen_change_before_first_instruction=False)
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(
                PATH, preimage(example_calldata(), chain_id=2, contract=TEST_CONTRACT),
                contract_descriptor=make_test_descriptor()):
            pass
    assert exc.value.status == Errors.SW_CONTRACT_CALL_MISMATCH
    assert_revoked(backend)
