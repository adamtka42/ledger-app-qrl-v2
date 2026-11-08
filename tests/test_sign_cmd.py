import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ledgered.devices import Device
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavIns, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.bip import pack_derivation_path

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender, CLA, InsType, Errors, MAX_APDU_LEN,
)

from application_client.transaction_helpers import (
    SIGNING_CONTEXT, PK_LEN, SIG_LEN, get_public_key_chunks, get_signature_chunks,
)

from application_client.transaction import (
    build_transaction_preimage, rlp_length_prefix as _rlp_len, rlp_encode_bytes as _rlp_bytes,
)

# In this tests we check the behavior of the device when asked to sign a transaction

# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_short_tx(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # The path used for this entire test
    path: str = "m/44'/238'/0'/0/0"

    # Derive the key on-device and fetch the public key for verification
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)

    # Unsigned go-qrl sighash preimage (11 RLP fields)
    # RLP: type=02, chain_id=1, nonce=3, gas_tip_cap, gas_fee_cap, gas=25000,
    #      to=b94f...aaaa (64 bytes), value, data, access_list=empty,
    #      descriptor=[0x01, 0x00, 0x00] (ML-DSA-87), extra_params=empty
    transaction = bytes.fromhex("02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a000080c08301000080")

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=path, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        scenario_navigator.review_approve()

    # Collect the full detached signature and verify it independently:
    # the device signs keccak256(preimage) under the fixed 8-byte context.
    signature = get_signature_chunks(backend, client.get_async_response().data)
    assert len(signature) == SIG_LEN
    sighash = keccak.new(digest_bits=256, data=transaction).digest()
    assert ML_DSA_87.verify(public_key, sighash, signature, ctx=SIGNING_CONTEXT)
    # Tampered message must not verify
    assert not ML_DSA_87.verify(public_key, b"\x00" * 32, signature, ctx=SIGNING_CONTEXT)

# In this test we send to the device a transaction to trig a blind-signing flow
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
# def test_sign_tx_short_tx_blind_sign(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
#     # Use the app interface instead of raw interface
#     client = BoilerplateCommandSender(backend)
#     # The path used for this entire test
#     path: str = "m/44'/238'/0'/0/0"

#     # Create the transaction that will be sent to the device for signing
#     # transaction = Transaction(
#     #     nonce=1,
#     #     to="0x0000000000000000000000000000000000000000",
#     #     value=0,
#     #     memo="Blind-sign"
#     # ).serialize()
#     transaction = bytes.fromhex("aabbccddee")

#     # As it requires on-screen validation, the function is asynchronous.
#     # It will yield the result when the navigation is done
#     with client.sign_tx(path=path, transaction=transaction):
#         # Validate the on-screen request by performing the navigation appropriate for this device
#         scenario_navigator.review_approve_with_warning(warning_path="part1")

#     # The device as yielded the result, parse it and ensure that the signature is correct
#     response = client.get_async_response().data
#     print(response.hex())
#     # _, der_sig, _ = unpack_sign_tx_response(response)
#     # assert check_signature_validity(public_key, der_sig, transaction)
#     assert True

# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    path: str = "m/44'/238'/0'/0/0"

    # Unsigned go-qrl sighash preimage with 64-byte recipient
    transaction = bytes.fromhex("02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a000080c08301000080")

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=path, transaction=transaction):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_calldata_refused_when_blind_signing_disabled(backend: BackendInterface) -> None:
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    # Same transaction as the clear-signing case, but data is the non-empty 0x5544.
    transaction = bytes.fromhex("02f86401038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a0000825544c08301000080")
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_DENY


# --- streaming parser: the device no longer buffers the whole transaction -----

# Fields of the preimage used in test_sign_tx_short_tx, so that a transaction
# with arbitrary calldata can be built without a separate vector generator.
_TO = bytes.fromhex("b94f5374fce5edbc8e2a8697c15331677e6ebf0b" + "aa" * 44)
_REFERENCE_PREIMAGE = bytes.fromhex("02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a000080c08301000080")


def build_preimage(data: bytes, access_list: bytes = b"\xc0", to: bytes = _TO) -> bytes:
    """Build the reference transaction with configurable data, access list and recipient."""
    return build_transaction_preimage(chain_id=1, nonce=3, gas_tip_cap=2_000_000_000,
                                      gas_fee_cap=50_000_000_000, gas=25_000, to=to,
                                      value=100_000_000_000_000_000, data=data, access_list=access_list)


def enable_blind_signing(device: Device, navigator: Navigator) -> None:
    """Enable the setting through the same UI a user must navigate."""
    if device.is_nano:
        for text in ("App settings", "Blind signing", "Back"):
            navigator.navigate_until_text(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                text=text,
                screen_change_before_first_instruction=False,
            )
    else:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, (200, 113)),  # First setting: Blind signing.
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ],
            screen_change_before_first_instruction=False,
        )


@pytest.mark.parametrize("recipient,data", [
    pytest.param(b"", b"", id="contract_creation"),
    pytest.param(bytes(64), b"", id="zero_address"),
    pytest.param(b"", bytes.fromhex("60006000f3"), id="contract_creation_with_bytecode"),
])
def test_sign_tx_recipient(backend: BackendInterface,
                           request: pytest.FixtureRequest,
                           device: Device,
                           navigator: Navigator,
                           scenario_navigator: NavigateWithScenario,
                           recipient: bytes,
                           data: bytes) -> None:
    """Compare the recipient review screens and verify the exact signed preimage."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    review_name = f"{request.node.originalname}_{request.node.callspec.id}"
    if data:
        enable_blind_signing(device, navigator)
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)
    transaction = build_preimage(data, to=recipient)

    with client.sign_tx(path=path, transaction=transaction):
        if data:
            scenario_navigator.review_approve_with_warning(test_name=review_name)
        else:
            scenario_navigator.review_approve(test_name=review_name)

    signature = get_signature_chunks(backend, client.get_async_response().data)
    assert len(signature) == SIG_LEN
    sighash = keccak.new(digest_bits=256, data=transaction).digest()
    assert ML_DSA_87.verify(public_key, sighash, signature, ctx=SIGNING_CONTEXT)


def test_contract_creation_bytecode_refused_when_blind_signing_disabled(backend: BackendInterface) -> None:
    client = BoilerplateCommandSender(backend)
    transaction = build_preimage(bytes.fromhex("60006000f3"), to=b"")
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path="m/44'/238'/0'/0/0", transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("payload_field", ["calldata", "access_list"])
def test_sign_tx_large_payload(backend: BackendInterface,
                               device: Device,
                               navigator: Navigator,
                               scenario_navigator: NavigateWithScenario,
                               payload_field: str) -> None:
    """Sign a multi-APDU transaction and verify every streamed byte was hashed."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    enable_blind_signing(device, navigator)
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)
    assert len(public_key) == PK_LEN

    if payload_field == "calldata":
        transaction = build_preimage(bytes(range(256)) * 12)
    else:
        # One 64-byte address with 96 distinct 32-byte storage keys. Both
        # skipped fields must contribute to the sighash without being buffered.
        keys = b"".join(_rlp_bytes(i.to_bytes(32, "big")) for i in range(96))
        entry = _rlp_bytes(_TO) + _rlp_len(0xc0, len(keys)) + keys
        entries = _rlp_len(0xc0, len(entry)) + entry
        transaction = build_preimage(b"", _rlp_len(0xc0, len(entries)) + entries)
    assert len(transaction) > 3000

    with client.sign_tx(path=path, transaction=transaction):
        scenario_navigator.review_approve_with_warning(do_comparison=False)

    response = client.get_async_response()
    assert response is not None
    signature = get_signature_chunks(backend, response.data)
    assert len(signature) == SIG_LEN
    sighash = keccak.new(digest_bits=256, data=transaction).digest()
    assert ML_DSA_87.verify(public_key, sighash, signature, ctx=SIGNING_CONTEXT)

    # Change a byte in the skipped payload beyond the former 510-byte limit.
    tampered = bytearray(transaction)
    tampered[2 * MAX_APDU_LEN] ^= 1
    tampered_hash = keccak.new(digest_bits=256, data=tampered).digest()
    assert not ML_DSA_87.verify(public_key, tampered_hash, signature, ctx=SIGNING_CONTEXT)


def test_preimage_builder_matches_reference() -> None:
    assert build_preimage(b"") == _REFERENCE_PREIMAGE


def test_malformed_tx_rejected_while_streaming(backend: BackendInterface) -> None:
    """600 bytes of garbage split by the client into three APDUs.

    The streaming parser rejects the payload on the first chunk (0xaa is not
    an RLP list header), before any later APDU, any UI and without a buffer
    size limit: the former 510-byte limit and SW_WRONG_TX_LENGTH are gone.
    """
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    transaction = bytes([0x02]) + b"\xaa" * 599
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL


def test_large_calldata_refused_when_blind_signing_disabled(backend: BackendInterface) -> None:
    """A 3 kB calldata is streamed over 13 APDUs and decoded to the end.

    Blind signing is off by default, so the device refuses once the whole
    transaction has been parsed. Before the streaming parser the same payload
    was rejected on the third APDU by the 510-byte buffer limit, so SW_DENY
    here proves the limit is gone and the parser kept its position across
    all chunks.
    """
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    transaction = build_preimage(b"\xab" * 3000)
    assert len(transaction) > 3000
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_truncated_tx_rejected(backend: BackendInterface) -> None:
    """The last APDU arrives before the outer RLP list is complete."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=_REFERENCE_PREIMAGE[:-1]):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL


def test_trailing_bytes_rejected(backend: BackendInterface) -> None:
    """Bytes after the end of the outer RLP list must not be signed."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=_REFERENCE_PREIMAGE + b"\x00"):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL


@pytest.mark.parametrize("path", [
    "m/44'/238'/0/0/0",
    "m/44'/238'/0'/0'/0",
    "m/44'/238'/0'/0/0'",
    "m/44'/238'/0'/0",
])
@pytest.mark.parametrize("p1", [0x01, 0x02], ids=["more", "last"])
def test_rejected_sign_path_cannot_continue(backend: BackendInterface, path: str, p1: int) -> None:
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0,
                         data=pack_derivation_path(path))
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH

    # One type byte exercises both continuation commands without entering UI
    # even on the vulnerable implementation.
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=p1, p2=0,
                         data=_REFERENCE_PREIMAGE[:1])
    assert exc.value.status == Errors.SW_BAD_STATE
    assert not exc.value.data


@pytest.mark.parametrize("bad_start", [
    b"",
    b"\x00",
    pack_derivation_path("m/44'/238'/0'/0/0")[:-1],
], ids=["empty", "zero_path_length", "truncated_path"])
@pytest.mark.parametrize("p1", [0x01, 0x02], ids=["more", "last"])
def test_failed_sign_start_invalidates_previous_session(
    backend: BackendInterface, bad_start: bytes, p1: int
) -> None:
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0,
                     data=pack_derivation_path("m/44'/238'/0'/0/0"))
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0,
                     data=_REFERENCE_PREIMAGE[:10])

    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0, data=bad_start)
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH

    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=p1, p2=0,
                         data=_REFERENCE_PREIMAGE[:1])
    assert exc.value.status == Errors.SW_BAD_STATE
    assert not exc.value.data


@pytest.mark.parametrize("bad_p1,bad_p2,transaction,status", [
    (0x01, 0, b"\x03", Errors.SW_TX_PARSING_FAIL),
    (0x02, 0, _REFERENCE_PREIMAGE[:-1], Errors.SW_TX_PARSING_FAIL),
    (0x01, 0, _REFERENCE_PREIMAGE, Errors.SW_TX_PARSING_FAIL),
    (0x02, 0, build_preimage(b"\x00"), Errors.SW_DENY),
    (0x01, 0, b"", Errors.SW_WRONG_DATA_LENGTH),
    (0x02, 0, b"", Errors.SW_WRONG_DATA_LENGTH),
    (0x03, 0, b"\x02", Errors.SW_WRONG_P1P2),
    (0x01, 18, b"\x02", Errors.SW_WRONG_P1P2),
    (0x00, 1, b"\x02", Errors.SW_WRONG_P1P2),
    (0x00, 17, b"\x02", Errors.SW_WRONG_P1P2),
    (0x01, 1, b"\x02", Errors.SW_WRONG_P1P2),
    (0x01, 17, b"\x02", Errors.SW_WRONG_P1P2),
], ids=["malformed", "truncated", "finished_before_last", "blind_signing_disabled",
        "empty_more", "empty_last", "invalid_p1", "invalid_p2",
        "first_with_chunk_1", "first_with_chunk_17", "more_with_chunk_1", "more_with_chunk_17"])
@pytest.mark.parametrize("p1", [0x01, 0x02], ids=["more", "last"])
def test_failed_sign_stream_cannot_continue(
    backend: BackendInterface, bad_p1: int, bad_p2: int, transaction: bytes, status: Errors, p1: int
) -> None:
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0,
                     data=pack_derivation_path("m/44'/238'/0'/0/0"))
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=bad_p1, p2=bad_p2, data=transaction)
    assert exc.value.status == status

    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=p1, p2=0,
                         data=_REFERENCE_PREIMAGE[:1])
    assert exc.value.status == Errors.SW_BAD_STATE
    assert not exc.value.data


def test_new_transaction_cannot_export_previous_signature(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    """An unfinished export must not authorize the next receiving session."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)
    with client.sign_tx(path=path, transaction=_REFERENCE_PREIMAGE):
        scenario_navigator.review_approve(do_comparison=False)
    assert len(client.get_async_response().data) == 258
    # Leave chunks 1..17 unread, so the persistent export flag remains set.
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0,
                     data=pack_derivation_path(path))
    transaction = build_preimage(b"", to=bytes.fromhex("11" * 64))
    for receiving_data in (False, True):
        if receiving_data:
            backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0,
                             data=transaction[:1])
        for p2 in range(1, 18):
            with pytest.raises(ExceptionRAPDU) as exc:
                backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=p2)
            assert exc.value.status == Errors.SW_BAD_STATE
            assert not exc.value.data
    # Refused exports do not discard the valid stream or release the old signature.
    with backend.exchange_async(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=0,
                                data=transaction[1:]):
        scenario_navigator.review_approve(do_comparison=False)
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=transaction).digest()
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


def test_signature_export_rejects_payload_and_discards_session(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    client = BoilerplateCommandSender(backend)
    with client.sign_tx(path="m/44'/238'/0'/0/0", transaction=_REFERENCE_PREIMAGE):
        scenario_navigator.review_approve(do_comparison=False)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1, data=b"\x00")
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH
    for p2 in (1, 17):
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=p2)
        assert exc.value.status == Errors.SW_BAD_STATE
        assert not exc.value.data


def test_valid_sign_session_after_rejected_path(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario
) -> None:
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)

    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0,
                         data=pack_derivation_path("m/44'/238'/0/0/0"))
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH

    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0, data=pack_derivation_path(path))
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0, data=_REFERENCE_PREIMAGE[:1])
    with backend.exchange_async(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=0,
                                data=_REFERENCE_PREIMAGE[1:]):
        scenario_navigator.review_approve(do_comparison=False)

    signature = get_signature_chunks(backend, client.get_async_response().data)
    assert len(signature) == SIG_LEN
    sighash = keccak.new(digest_bits=256, data=_REFERENCE_PREIMAGE).digest()
    assert ML_DSA_87.verify(public_key, sighash, signature, ctx=SIGNING_CONTEXT)
