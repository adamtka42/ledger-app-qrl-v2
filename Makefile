# ****************************************************************************
#    Ledger App Boilerplate
#    (c) 2023 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "QRL v2.0"

# Application version
APPVERSION_M = 2
APPVERSION_N = 2
APPVERSION_P = 2
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/app_qrl_14px.gif
ICON_NANOSP = icons/app_qrl_14px.gif
ICON_STAX = icons/app_qrl_32px.gif
ICON_FLEX = icons/app_qrl_40px.gif

# With the Nano NBGL Design, the Home Screen icon is the reverse of the App icon:
# It should be on white background, with rounded corners.
# This definition allows SDK Makefiles to automatically generate it based on the App icon.
# Please note that the icon is dynamically generated, and declared in the .gitignore to avoid storing it.
ICON_HOME_NANO = glyphs/home_qrl_14px.gif

# Application allowed derivation curves.
# Possibles curves are: secp256k1, secp256r1, ed25519 and bls12381g1
# If your app needs it, you can specify multiple curves by using:
# `CURVE_APP_LOAD_PARAMS = <curve1> <curve2>`
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
# You should request a specific path for your app.
# This serve as an isolation mechanism.
# Most application will have to request a path according to the BIP-0044
# and SLIP-0044 standards.
# If your app needs it, you can specify multiple path by using:
# `PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'"`
PATH_APP_LOAD_PARAMS = "44'/238'"   # purpose=44' / coin_type=238' (QRL)

# Setting to allow building variant applications
# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = QRL

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

# ML-DSA-87 uses about 19500 bytes of application stack in emulator measurements.
# Fail linking if static buffers leave less than this budget. Hardware syscall
# overhead still needs validation on a physical Nano X.
APP_STACK_MIN_SIZE = 20500

########################################
#        Token metadata issuer         #
########################################
# Optional trusted issuer for QRL token metadata: its uncompressed SEC1 P-256
# public key as 130 hex characters (04 || x || y). Without an issuer the
# metadata command is rejected; native transfers and blind signing still work.
#   make TOKEN_METADATA_PUBLIC_KEY=04<x><y>
# The key is validated and decoded here so that a misconfigured value stops the
# build instead of shipping firmware that rejects every descriptor at runtime.
# INSECURE public test authority (P-256 generator, private scalar 1): only
# selectable through TOKEN_METADATA_TEST_KEY=1, which also requires DEBUG=1.
TOKEN_METADATA_TEST_PUBLIC_KEY := 046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
ifneq ($(TOKEN_METADATA_PUBLIC_KEY),)
ifeq ($(TOKEN_METADATA_TEST_KEY),1)
$(error Select either TOKEN_METADATA_PUBLIC_KEY or TOKEN_METADATA_TEST_KEY)
endif
# Lower-case the value, then strip every hex digit: anything left is not hex.
token_key := $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(TOKEN_METADATA_PUBLIC_KEY)))))))
token_key_rest := $(token_key)
$(foreach c,0 1 2 3 4 5 6 7 8 9 a b c d e f,$(eval token_key_rest := $$(subst $(c),,$$(token_key_rest))))
ifneq ($(token_key_rest),)
$(error TOKEN_METADATA_PUBLIC_KEY must contain only hex digits, without a 0x prefix)
endif
# Only hex digits remain, so the value is safe to hand to the shell.
ifneq ($(shell printf '%s' '$(token_key)' | grep -Ecx '04[0-9a-f]{128}'),1)
$(error TOKEN_METADATA_PUBLIC_KEY must be 130 hex characters starting with 04 (uncompressed SEC1 P-256 key))
endif
ifeq ($(token_key),$(TOKEN_METADATA_TEST_PUBLIC_KEY))
$(error TOKEN_METADATA_PUBLIC_KEY is the public test authority; use DEBUG=1 TOKEN_METADATA_TEST_KEY=1 instead)
endif
# Python's standard library checks coordinate ranges and the P-256 equation.
# The hex-only validation above keeps the shell argument safe.
token_key_bytes := $(shell python3 tools/token_metadata_key.py '$(token_key)')
ifeq ($(token_key_bytes),)
$(error TOKEN_METADATA_PUBLIC_KEY validation failed; a valid P-256 point and Python 3 are required)
endif
DEFINES += TOKEN_METADATA_PUBLIC_KEY_BYTES=$(token_key_bytes)
endif
ifeq ($(TOKEN_METADATA_TEST_KEY),1)
ifneq ($(DEBUG),1)
$(error TOKEN_METADATA_TEST_KEY=1 requires DEBUG=1; never use it for release builds)
endif
DEFINES += TOKEN_METADATA_TEST_KEY
endif

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
#HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_DEBUG_LEDGER_ASSERT = 1
#DISABLE_DEBUG_THROW = 1

include $(BOLOS_SDK)/Makefile.standard_app
