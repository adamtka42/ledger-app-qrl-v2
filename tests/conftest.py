import pytest
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import Errors
from application_client.token_calls import start, provide
from application_client.token_metadata import make_test_metadata

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
