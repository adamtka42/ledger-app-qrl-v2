"""Clear review of pinned Zond deposits, never broadcasting to a network."""
import pytest
from ragger.error import ExceptionRAPDU
from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.staking import synthetic_deposit, TEST_CONTRACT, MIN_SHOR
from application_client.transaction import build_transaction_preimage
from application_client.token_calls import PATH, enable_nonce_and_hash
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks


def deposit_tx(data=None, *, shor=MIN_SHOR, **kwargs):
    options = dict(chain_id=1, nonce=3, gas_tip_cap=0, gas_fee_cap=2550000000, gas=500000,
                   to=kwargs.pop("contract", TEST_CONTRACT), value=kwargs.pop("value", shor * 10**9),
                   data=synthetic_deposit(shor) if data is None else data)
    options.update(kwargs)
    return build_transaction_preimage(**options)


def assert_revoked(backend):
    with pytest.raises(ExceptionRAPDU) as exc:
        backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("case", ["approve", "reject", "details", "maximum"])
def test_staking_review(backend, staking_profile, device, navigator, scenario_navigator, case):
    if case == "details":
        enable_nonce_and_hash(backend, device, navigator)
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    shor = 2**64 - 1 if case == "maximum" else MIN_SHOR
    tx = deposit_tx(shor=shor)
    if case == "reject":
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_tx(PATH, tx):
                scenario_navigator.review_reject(test_name="test_staking_reject")
        assert exc.value.status == Errors.SW_DENY
        assert_revoked(backend)
        return
    with client.sign_tx(PATH, tx):
        scenario_navigator.review_approve(test_name=f"test_staking_{case}",
                                          custom_screen_text=r"^Sign staking" if device.is_nano else None)
    signature = get_signature_chunks(backend, client.get_async_response().data)
    digest = keccak.new(digest_bits=256, data=tx).digest()
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    changed = keccak.new(digest_bits=256, data=deposit_tx(shor=shor - 1)).digest()
    assert not ML_DSA_87.verify(public_key, changed, signature, ctx=SIGNING_CONTEXT)
    assert_revoked(backend)


@pytest.mark.parametrize("mutation", [
    "offset", "high_offset", "root", "root_padding", "pubkey_length", "pubkey", "pubkey_padding",
    "withdrawal_length", "withdrawal", "randao_length", "randao", "randao_padding",
    "signature_length", "signature", "signature_padding", "short", "trailing",
    "amount", "fractional_shor", "too_small", "overflow", "access_list",
])
def test_staking_invalid(backend, staking_profile, mutation):
    data = bytearray(synthetic_deposit())
    kwargs = {}
    indices = {"offset": 67, "high_offset": 4, "root": 260, "root_padding": 292,
               "pubkey_length": 387, "pubkey": 1200, "pubkey_padding": 2980,
               "withdrawal_length": 3075, "withdrawal": 3076, "randao_length": 3203,
               "randao": 3204, "randao_padding": 3236, "signature_length": 3331,
               "signature": 7000, "signature_padding": 7959}
    if mutation in indices: data[indices[mutation]] ^= 1
    elif mutation == "short": data = data[:-1]
    elif mutation == "trailing": data += b"\0"
    elif mutation == "amount": kwargs["value"] = (MIN_SHOR + 1) * 10**9
    elif mutation == "fractional_shor": kwargs["value"] = MIN_SHOR * 10**9 + 1
    elif mutation == "too_small":
        data = bytearray(synthetic_deposit(MIN_SHOR - 1))
        kwargs["value"] = (MIN_SHOR - 1) * 10**9
    elif mutation == "overflow": kwargs["value"] = (2**64 + MIN_SHOR) * 10**9
    elif mutation == "access_list": kwargs["access_list"] = b"\xc1\x80"
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(PATH, deposit_tx(bytes(data), **kwargs)):
            pass
    assert exc.value.status == Errors.SW_STAKING_DEPOSIT_INVALID
    assert_revoked(backend)


@pytest.mark.parametrize("mutation", ["chain", "high_chain", "contract", "selector", "creation"])
def test_staking_wrong_target_requires_blind(backend, mutation):
    data = bytearray(synthetic_deposit())
    kwargs = {}
    if mutation == "chain": kwargs["chain_id"] = 2
    elif mutation == "high_chain": kwargs["chain_id"] = 2**128 + 1
    elif mutation == "contract": kwargs["contract"] = b"\x43" * 64
    elif mutation == "selector": data[0] ^= 1
    else: kwargs["contract"] = b""
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(PATH, deposit_tx(bytes(data), **kwargs)):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_staking_default_build_requires_blind(backend, request):
    if request.config.getoption("--staking-deposit-test-profile"):
        pytest.skip("This assertion targets a build without a pinned staking deployment")
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(PATH, deposit_tx()):
            pass
    assert exc.value.status == Errors.SW_DENY


@pytest.mark.parametrize("kind", ["token", "contract"])
def test_staking_cannot_mix_signed_metadata(backend, staking_profile, request, kind):
    from application_client.token_metadata import make_test_metadata
    from application_client.contract_calls import make_test_descriptor
    request.getfixturevalue("token_issuer" if kind == "token" else "contract_issuer")
    metadata = ({"token_metadata": make_test_metadata(contract=TEST_CONTRACT)} if kind == "token"
                else {"contract_descriptor": make_test_descriptor(contract=TEST_CONTRACT)})
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(PATH, deposit_tx(), **metadata):
            pass
    assert exc.value.status == Errors.SW_BAD_STATE
    assert_revoked(backend)


def test_staking_invalid_is_rejected_with_blind_enabled(backend, staking_profile, device, navigator):
    from ragger.navigator import NavIns, NavInsID
    if device.is_nano:
        for text in ("App settings", "Blind signing", "Back"):
            navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], text=text,
                                           screen_change_before_first_instruction=False)
    else:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS, NavIns(NavInsID.TOUCH, (200, 113)),
                            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                           screen_change_before_first_instruction=False)
    data = bytearray(synthetic_deposit()); data[260] ^= 1
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_tx(PATH, deposit_tx(bytes(data))):
            pass
    assert exc.value.status == Errors.SW_STAKING_DEPOSIT_INVALID
    assert_revoked(backend)


def test_staking_rendered_fields(backend, staking_profile, device, scenario_navigator, monkeypatch):
    import re
    from application_client.staking import merkle_root
    data = synthetic_deposit()
    tx = deposit_tx(data)
    names = (["Validator root", "Withdraw to", "RANDAO", "Deposit root"] if device.is_nano else
             ["Validator key root", "Withdraw to", "RANDAO commitment", "Deposit data root"])
    expected = dict(zip(names, [merkle_root(data[388:2980]).hex(), "Q" + "11" * 64,
                                data[3204:3236].hex(), data[260:292].hex()]))
    pages = {name: {} for name in names}
    all_rows = set(names + ["From", "Amount", "Contract", "Deposit contract", "Operation", "Chain ID",
                           "Gas limit", "Priority fee / gas", "Max fees", "Nonce", "Transaction hash"])
    original = backend.compare_screen_with_text

    def capture(pattern):
        texts = [event.get("text", "") for event in backend.get_current_screen_content()["events"]]
        assert "More" not in texts
        for index, text in enumerate(texts):
            name = re.sub(r" \(\d+/\d+\)$", "", text)
            if name not in expected:
                continue
            following = []
            for item in texts[index + 1:]:
                if item in all_rows or item == "Reject" or re.fullmatch(r"\d+ of \d+", item):
                    break
                following.append(item)
            value = "".join(following).replace("\n", "")
            if text in pages[name]:
                assert pages[name][text] == value
            pages[name][text] = value
        return original(pattern)

    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    monkeypatch.setattr(backend, "compare_screen_with_text", capture)
    with client.sign_tx(PATH, tx):
        scenario_navigator.review_approve(do_comparison=False,
                                          custom_screen_text=r"^Sign staking" if device.is_nano else None)
    for name in names:
        assert "".join(pages[name].values()) == expected[name], (name, pages[name])
    signature = get_signature_chunks(backend, client.get_async_response().data)
    assert ML_DSA_87.verify(public_key, keccak.new(digest_bits=256, data=tx).digest(),
                            signature, ctx=SIGNING_CONTEXT)
