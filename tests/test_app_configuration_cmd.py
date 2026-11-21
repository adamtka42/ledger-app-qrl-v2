"""Read live settings through APDU without changing UI or signing sessions."""
import pytest
from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavIns, NavInsID

from application_client.app_configuration import AppConfiguration
from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors


PATH = "m/44'/238'/0'/0/0"
# Existing native go-qrl sighash vector, split below to exercise a receiving session.
PREIMAGE = bytes.fromhex(
    "02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0b"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "88016345785d8a000080c08301000080"
)


def read_configuration(backend):
    reply = BoilerplateCommandSender(backend).get_app_configuration()
    assert reply.status == 0x9000
    return AppConfiguration.from_bytes(reply.data)


def toggle_setting(backend, device, navigator, label):
    if device.is_nano:
        for text in ("App settings", label, "Back"):
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK],
                                           text=text, screen_change_before_first_instruction=False)
    else:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS],
                           screen_change_before_first_instruction=False)
        navigator.navigate_until_text(NavInsID.USE_CASE_SETTINGS_NEXT, [], text=label,
                                       screen_change_before_first_instruction=False)
        events = backend.get_current_screen_content()["events"]
        row = next(event for event in events if event.get("text") == label)
        navigator.navigate([NavIns(NavInsID.TOUCH, (200, row["y"] + 5)),
                            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                           screen_change_before_first_instruction=False)


def test_configuration_default_and_version(backend):
    client = BoilerplateCommandSender(backend)
    config = read_configuration(backend)
    assert config.flags == 0
    assert not config.blind_signing_enabled
    assert not config.display_nonce
    assert not config.display_tx_hash
    assert bytes(config.version) == client.get_version().data
    assert read_configuration(backend) == config


def test_configuration_tracks_ui_settings(backend, device, navigator):
    assert read_configuration(backend).flags == 0
    for label, bit in (("Blind signing", 1), ("Nonce", 2), ("Transaction hash", 4)):
        toggle_setting(backend, device, navigator, label)
        assert read_configuration(backend).flags == bit
        toggle_setting(backend, device, navigator, label)
        assert read_configuration(backend).flags == 0


@pytest.mark.parametrize("p1,p2,payload,status", [
    (1, 0, b"", Errors.SW_WRONG_P1P2),
    (0, 1, b"", Errors.SW_WRONG_P1P2),
    (255, 255, b"", Errors.SW_WRONG_P1P2),
    (0, 0, b"\0", Errors.SW_WRONG_DATA_LENGTH),
    (0, 0, bytes(255), Errors.SW_WRONG_DATA_LENGTH),
])
def test_configuration_invalid_request(backend, p1, p2, payload, status):
    before = read_configuration(backend)
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.GET_APP_CONFIGURATION,
                          p1=p1, p2=p2, data=payload)
    assert exc.value.status == status
    assert read_configuration(backend) == before


def test_configuration_preserves_stream_and_signature_export(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = b"".join(backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY,
                                          p1=0, p2=i).data for i in range(1, 12))[:2592]
    before = read_configuration(backend)
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0,
                      data=pack_derivation_path(PATH))
    assert read_configuration(backend) == before
    split = len(PREIMAGE) // 2
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=1, p2=0, data=PREIMAGE[:split])
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.GET_APP_CONFIGURATION, p1=0, p2=0, data=b"\0")
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH
    assert read_configuration(backend) == before
    with backend.exchange_async(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=0,
                                data=PREIMAGE[split:]):
        scenario_navigator.review_approve(do_comparison=False)
    signature = backend.last_async_response.data
    for index in range(1, 18):
        assert read_configuration(backend) == before
        signature += backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=index).data
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, keccak.new(digest_bits=256, data=PREIMAGE).digest(),
                            signature, ctx=bytes.fromhex("5a4f4e4401010000"))
