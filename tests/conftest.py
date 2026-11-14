
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
