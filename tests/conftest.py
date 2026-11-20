import pytest
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.staking import synthetic_deposit, TEST_CONTRACT, MIN_SHOR
from application_client.token_calls import PATH, start, provide
from application_client.transaction import build_transaction_preimage
from application_client.token_metadata import make_test_metadata
from application_client.contract_calls import make_test_descriptor

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


def pytest_addoption(parser):
    parser.addoption("--staking-deposit-test-profile", action="store_true",
                     help="Require DEBUG=1 STAKING_DEPOSIT_TEST_PROFILE=1.")
    parser.addoption(
        "--contract-descriptor-test-key", action="store_true",
        help="Require contract descriptor test issuer (DEBUG=1 CONTRACT_DESCRIPTOR_TEST_KEY=1).",
    )
    parser.addoption(
        "--token-metadata-test-key",
        action="store_true",
        help="Require token metadata verification with the test issuer (DEBUG=1 TOKEN_METADATA_TEST_KEY=1).",
    )


@pytest.fixture
def token_issuer(backend, request):
    start(backend)
    try:
        provide(backend, make_test_metadata())
    except ExceptionRAPDU as exc:
        if exc.status == Errors.SW_TOKEN_METADATA_NO_ISSUER:
            if request.config.getoption("--token-metadata-test-key"):
                pytest.fail("No token metadata issuer configured; expected DEBUG=1 TOKEN_METADATA_TEST_KEY=1")
            pytest.skip("Requires a build with DEBUG=1 TOKEN_METADATA_TEST_KEY=1")
        raise


@pytest.fixture
def contract_issuer(backend, request):
    start(backend)
    try:
        backend.exchange(cla=0xE0, ins=0x0B, p1=0, p2=0, data=make_test_descriptor())
    except ExceptionRAPDU as exc:
        if exc.status == Errors.SW_CONTRACT_DESCRIPTOR_NO_ISSUER:
            if request.config.getoption("--contract-descriptor-test-key"):
                pytest.fail("No contract issuer configured; expected DEBUG=1 CONTRACT_DESCRIPTOR_TEST_KEY=1")
            pytest.skip("Requires DEBUG=1 CONTRACT_DESCRIPTOR_TEST_KEY=1")
        raise


@pytest.fixture
def staking_test_profile_present(backend) -> bool:
    """Ask the app itself: a deposit with a corrupted root is rejected as an
    invalid deposit only by a build that pins the test staking deployment;
    any other build treats it as opaque calldata and requires blind signing."""
    data = bytearray(synthetic_deposit())
    data[260] ^= 1
    tx = build_transaction_preimage(chain_id=1, nonce=3, gas_tip_cap=0, gas_fee_cap=2550000000,
                                    gas=500000, to=TEST_CONTRACT, value=MIN_SHOR * 10**9,
                                    data=bytes(data))
    try:
        with BoilerplateCommandSender(backend).sign_tx(PATH, tx):
            pass
    except ExceptionRAPDU as exc:
        if exc.status == Errors.SW_STAKING_DEPOSIT_INVALID:
            return True
        if exc.status == Errors.SW_DENY:
            return False
        raise
    pytest.fail("A corrupted staking deposit was not rejected")


@pytest.fixture
def staking_profile(staking_test_profile_present, request):
    if staking_test_profile_present:
        return
    if request.config.getoption("--staking-deposit-test-profile"):
        pytest.fail("No staking deployment pinned; expected DEBUG=1 STAKING_DEPOSIT_TEST_PROFILE=1")
    pytest.skip("Requires DEBUG=1 STAKING_DEPOSIT_TEST_PROFILE=1")
