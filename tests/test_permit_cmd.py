"""Token spending permits: typed data clear-signed with issuer-signed token metadata."""
import pytest
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.token_metadata import TEST_CONTRACT, make_test_metadata
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks
from application_client.typed_data import DOMAIN_TYPE, PATH, encode_typed_data, permit_example, typed_data_hash

MAX_UINT256 = 2**256 - 1
OTHER_OWNER = bytes.fromhex("44" * 64)
PERMIT_TITLES = ("TEST token permit", "TEST revoke permit", "TEST unlimited permit")


def signer_address(client):
    """The device answers with "Q" followed by the 64-byte address."""
    response = client.get_public_key(PATH).data
    assert len(response) == 65 and response[:1] == b"Q"
    return response[1:]


def confirmation_text(device):
    # Touch devices confirm with their Hold to sign control.
    return r"^Sign (token|unlimited)" if device.is_nano else None


def start(backend, length):
    return backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=0, p2=0,
                            data=pack_derivation_path(PATH) + length.to_bytes(4, "big"))


def provide(backend, payload):
    return backend.exchange(cla=CLA, ins=InsType.PROVIDE_TOKEN_METADATA, p1=0, p2=0, data=payload)


def record_screens(backend, monkeypatch):
    """Collect every text shown while a review is navigated."""
    texts = []
    compare_text = backend.compare_screen_with_text

    def capture(*args, **kwargs):
        texts.extend(event.get("text", "") for event in backend.get_current_screen_content()["events"])
        return compare_text(*args, **kwargs)

    monkeypatch.setattr(backend, "compare_screen_with_text", capture)
    return texts


def shows_permit(texts):
    # A title may wrap over two lines on Nano.
    shown = " ".join(" ".join(texts).split())
    return any(title in shown for title in PERMIT_TITLES)


def sign_and_verify(backend, client, public_key, doc, navigate, **kwargs):
    with client.sign_typed_data(PATH, encode_typed_data(doc), **kwargs):
        navigate()
    signature = get_signature_chunks(backend, client.get_async_response().data,
                                     ins=InsType.SIGN_TYPED_DATA)
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, typed_data_hash(doc), signature, ctx=SIGNING_CONTEXT)
    return signature


@pytest.mark.parametrize("case,value,deadline,own", [
    ("limited", 25_000_000, 2_000_000_000, True),
    ("revoke", 0, 2_000_000_000, True),
    ("unlimited", MAX_UINT256, MAX_UINT256, True),
    ("large_limited", MAX_UINT256 - 1, 253_402_300_799, True),
    ("other_owner", 1, 0, False),
])
def test_permit_review(backend, token_issuer, device, scenario_navigator, monkeypatch,
                       case, value, deadline, own):
    client = BoilerplateCommandSender(backend)
    signer = signer_address(client)
    owner = signer if own else OTHER_OWNER
    public_key = get_public_key_chunks(backend)
    doc = permit_example(owner, value=value, deadline=deadline)
    texts = record_screens(backend, monkeypatch)
    signature = sign_and_verify(
        backend, client, public_key, doc,
        lambda: scenario_navigator.review_approve(test_name=f"test_permit_{case}",
                                                  custom_screen_text=confirmation_text(device)),
        token_metadata=make_test_metadata())
    assert shows_permit(texts)
    assert "Review typed data" not in texts and "Primary type" not in texts
    assert any(text.startswith("Token owner") for text in texts) != own
    # The signature covers every value that was reviewed.
    for changed in (permit_example(owner, value=(value + 1) % 2**256, deadline=deadline),
                    permit_example(owner, value=value, deadline=deadline, spender=b"\x33" * 64),
                    permit_example(owner, value=value, deadline=(deadline + 1) % 2**256)):
        assert not ML_DSA_87.verify(public_key, typed_data_hash(changed), signature, ctx=SIGNING_CONTEXT)


def test_permit_refused(backend, token_issuer, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    doc = permit_example(signer_address(client))
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_typed_data(PATH, encode_typed_data(doc), token_metadata=make_test_metadata()):
            scenario_navigator.review_reject(test_name="test_permit_refused")
    assert exc.value.status == Errors.SW_DENY
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=2, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


def other_token():
    return make_test_metadata(contract=bytes.fromhex("55" * 64))


def other_chain():
    return make_test_metadata(chain_id=2)


def renamed(doc):
    doc["types"]["Permission"] = doc["types"].pop("Permit")
    doc["primaryType"] = "Permission"


def reordered(doc):
    fields = doc["types"]["Permit"]
    fields[2], fields[3] = fields[3], fields[2]


def narrowed(doc):
    doc["types"]["Permit"][2]["type"] = "uint128"


def extended(doc):
    doc["types"]["Permit"].append({"name": "memo", "type": "string"})
    doc["message"]["memo"] = "extra"


def salted(doc):
    doc["types"][DOMAIN_TYPE].append({"name": "salt", "type": "bytes32"})
    doc["domain"]["salt"] = "0x" + "66" * 32


def unbound(doc):
    doc["types"][DOMAIN_TYPE] = doc["types"][DOMAIN_TYPE][:3]
    del doc["domain"]["verifyingContract"]


@pytest.mark.parametrize("metadata,mutation", [
    (other_token, None), (other_chain, None), (None, None),
    (make_test_metadata, renamed), (make_test_metadata, reordered), (make_test_metadata, narrowed),
    (make_test_metadata, extended), (make_test_metadata, salted), (make_test_metadata, unbound),
], ids=["other_token", "other_chain", "no_metadata", "renamed", "reordered", "narrowed",
        "extended", "salted", "unbound"])
def test_unrecognised_permit_keeps_generic_review(backend, token_issuer, scenario_navigator,
                                                  monkeypatch, metadata, mutation):
    """Anything but the exact permit of the verified token shows every raw field."""
    client = BoilerplateCommandSender(backend)
    doc = permit_example(signer_address(client))
    if mutation is not None:
        mutation(doc)
    public_key = get_public_key_chunks(backend)
    texts = record_screens(backend, monkeypatch)
    sign_and_verify(backend, client, public_key, doc,
                    lambda: scenario_navigator.review_approve(do_comparison=False),
                    token_metadata=metadata() if metadata is not None else None)
    assert "Review typed data" in texts and "Primary type" in texts
    assert not shows_permit(texts)
    assert not any(text.startswith("Spending limit") for text in texts)


def test_permit_metadata_wrong_issuer_aborts_session(backend, token_issuer):
    payload = encode_typed_data(permit_example(OTHER_OWNER))
    start(backend, len(payload))
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_metadata(scalar=2))
    assert exc.value.status == Errors.SW_TOKEN_METADATA_UNTRUSTED
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=1, p2=0, data=payload[:10])
    assert exc.value.status == Errors.SW_BAD_STATE


def test_permit_metadata_requires_fresh_session(backend, token_issuer):
    payload = encode_typed_data(permit_example(OTHER_OWNER))
    start(backend, len(payload))
    backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=1, p2=0, data=payload[:10])
    with pytest.raises(ExceptionRAPDU) as exc:
        provide(backend, make_test_metadata())
    assert exc.value.status == Errors.SW_BAD_STATE
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=1, p2=0, data=payload[10:20])
    assert exc.value.status == Errors.SW_BAD_STATE


def test_permit_metadata_does_not_survive_new_session(backend, token_issuer, scenario_navigator,
                                                      monkeypatch):
    client = BoilerplateCommandSender(backend)
    doc = permit_example(signer_address(client))
    public_key = get_public_key_chunks(backend)
    start(backend, len(encode_typed_data(doc)))
    provide(backend, make_test_metadata())
    texts = record_screens(backend, monkeypatch)
    sign_and_verify(backend, client, public_key, doc,
                    lambda: scenario_navigator.review_approve(do_comparison=False))
    assert "Review typed data" in texts
    assert not shows_permit(texts)
