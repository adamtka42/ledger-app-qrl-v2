import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.personal_message import PATH, MAX_MESSAGE_LEN, personal_message_hash, start_message, send_message
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks

MAXIMUM_SUFFIX = b"END-MAXIMUM-TEXT!"

@pytest.mark.parametrize("message,case,decision", [
    (b"Login to example.app\nNonce: 123456", "login", "approve"),
    (b"", "empty", "approve"),
    (b"0x1234", "literal_hex", "approve"),
    (b"Page content 0123456789. " * 12 + b"END OF MESSAGE", "long", "approve"),
    ((b"W" * 30 + b"\n") * 32 + b"END OF LINES", "newline_limit", "approve"),
    (b"A" * (MAX_MESSAGE_LEN - len(MAXIMUM_SUFFIX)) + MAXIMUM_SUFFIX, "maximum", "approve"),
    (b"Login to example.app\nNonce: 123456", "login", "reject"),
])
def test_personal_message_review(backend, scenario_navigator, message, case, decision):
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    name = f"test_personal_message_{case}_{decision}"
    if decision == "reject":
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_personal_message(PATH, message):
                scenario_navigator.review_reject(test_name=name)
        assert exc.value.status == Errors.SW_DENY
        with pytest.raises(ExceptionRAPDU) as exc:
            send_message(backend, p2=1)
        assert exc.value.status == Errors.SW_BAD_STATE
        return
    with client.sign_personal_message(PATH, message):
        scenario_navigator.review_approve(test_name=name)
    # Signature chunks are bound to this command, not SIGN_TX.
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE
    signature = get_signature_chunks(backend, client.get_async_response().data,
                                      ins=InsType.SIGN_PERSONAL_MESSAGE)
    digest = personal_message_hash(message)
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    assert not ML_DSA_87.verify(public_key, digest, signature, ctx=b"")
    for wrong_hash in (personal_message_hash(message + b"!"),
                       personal_message_hash(message, b"\x19Ethereum Signed Message:\n"),
                       keccak.new(digest_bits=256, data=message).digest()):
        assert not ML_DSA_87.verify(public_key, wrong_hash, signature, ctx=SIGNING_CONTEXT)
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("payload", [b"\0", b"\t", b"\r", b"\x19", b"\x1b", b"\x7f", b"\xff", "żółw".encode(), b"\n" * 33])
def test_personal_message_rejects_unreviewable_text(backend, payload):
    start_message(backend, len(payload))
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, payload)
    assert exc.value.status == Errors.SW_MESSAGE_INVALID
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"x")
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("payload", [b"", b"\0", pack_derivation_path(PATH),
    pack_derivation_path(PATH) + b"\0" * 3,
    pack_derivation_path(PATH) + b"\0" * 5,
    pack_derivation_path("m/44'/60'/0'/0/0") + b"\0" * 4,
    pack_derivation_path(PATH) + (MAX_MESSAGE_LEN + 1).to_bytes(4, "big"),
    pack_derivation_path(PATH) + b"\xff" * 4])
def test_personal_message_bad_start_aborts(backend, payload):
    start_message(backend, 1)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_PERSONAL_MESSAGE, p1=0, p2=0, data=payload)
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"x")
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("p1,p2", [(3, 0), (0, 1), (1, 1), (2, 18), (255, 255)])
def test_personal_message_bad_parameters_abort(backend, p1, p2):
    start_message(backend, 1)
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"x", p1=p1, p2=p2)
    assert exc.value.status == Errors.SW_WRONG_P1P2
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"x")
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("expected,data,p1", [(2, b"a", 2), (1, b"ab", 2), (1, b"", 2),
                                             (1, b"", 1), (1, b"a", 1), (0, b"x", 2)])
def test_personal_message_length_mismatch(backend, expected, data, p1):
    start_message(backend, expected)
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, data, p1=p1)
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


def test_personal_message_session_isolation(backend):
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"x")
    assert exc.value.status == Errors.SW_BAD_STATE
    start_message(backend, 2)
    send_message(backend, b"a", p1=1)
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE
    # An address derivation cancels the message session.
    BoilerplateCommandSender(backend).get_public_key(PATH)
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"b")
    assert exc.value.status == Errors.SW_BAD_STATE
    start_message(backend, 2)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0, data=b"a")
    assert exc.value.status == Errors.SW_BAD_STATE
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0, data=pack_derivation_path(PATH))
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, b"a", p1=1)
    assert exc.value.status == Errors.SW_BAD_STATE


def test_new_session_cannot_export_previous_message_signature(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    with client.sign_personal_message(PATH, b"Session isolation"):
        scenario_navigator.review_approve(test_name="test_personal_message_session_isolation")
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0, data=pack_derivation_path(PATH))
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE
    start_message(backend, 1)
    with pytest.raises(ExceptionRAPDU) as exc:
        send_message(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE
