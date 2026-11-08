"""Shared token transaction/session builders and settings navigation."""
from ragger.bip import pack_derivation_path
from ragger.navigator import NavIns, NavInsID

from .boilerplate_command_sender import CLA, InsType
from .token_metadata import TEST_CONTRACT, transfer_calldata
from .transaction import build_transaction_preimage

PATH = "m/44'/238'/0'/0/0"


def preimage(data=None, *, chain_id=1, contract=TEST_CONTRACT, value=0, access_list=b"\xc0"):
    if data is None:
        data = transfer_calldata(10_000_000)
    return build_transaction_preimage(chain_id=chain_id, nonce=3, gas_tip_cap=0,
                                      gas_fee_cap=2_550_000_000, gas=100_000, to=contract,
                                      value=value, data=data, access_list=access_list)


def start(backend):
    backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=0, p2=0, data=pack_derivation_path(PATH))


def provide(backend, payload, *, p1=0, p2=0):
    return backend.exchange(cla=CLA, ins=InsType.PROVIDE_TOKEN_METADATA,
                            p1=p1, p2=p2, data=payload)


def enable_nonce_and_hash(backend, device, navigator):
    if device.is_nano:
        for text in ("App settings", "Nonce", "Transaction hash", "Back"):
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK],
                                           text=text, screen_change_before_first_instruction=False)
    else:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS],
                           screen_change_before_first_instruction=False)
        for text in ("Nonce", "Transaction hash"):
            navigator.navigate_until_text(NavInsID.USE_CASE_SETTINGS_NEXT, [], text=text,
                                           screen_change_before_first_instruction=False)
            # Locate the setting's row: pagination and spacing differ on Flex and Stax.
            events = backend.get_current_screen_content()["events"]
            row = next(event for event in events if event.get("text") == text)
            navigator.navigate([NavIns(NavInsID.TOUCH, (200, row["y"] + 5))],
                               screen_change_before_first_instruction=False)
        navigator.navigate([NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                           screen_change_before_first_instruction=False)
