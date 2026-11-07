"""Exercise issuer validation through the real Makefile without the Ledger SDK."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
# Independently known P-256 point 2*G; the public test authority is G.
ISSUER = (
    "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
    "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
)
TEST_ISSUER = (
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


class IssuerBuildTests(unittest.TestCase):
    def setUp(self):
        self.sdk = tempfile.TemporaryDirectory()
        self.addCleanup(self.sdk.cleanup)
        Path(self.sdk.name, "Makefile.standard_app").write_text(
            ".PHONY: print_issuer\nprint_issuer:\n\t@printf '%s' '$(DEFINES)'\n"
        )

    def build_config(self, *settings):
        env = os.environ.copy()
        for name in list(env):
            if name.startswith("TOKEN_METADATA_") or name in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES"):
                del env[name]
        return subprocess.run(
            ["make", "--no-print-directory", "-f", "Makefile", "print_issuer",
             f"BOLOS_SDK={self.sdk.name}", *settings],
            cwd=REPO, env=env, text=True, capture_output=True,
        )

    def test_valid_issuer_is_decoded_exactly(self):
        expected = ",".join(f"0x{byte:02x}" for byte in bytes.fromhex(ISSUER))
        for key in (ISSUER, ISSUER.upper()):
            with self.subTest(key=key):
                result = self.build_config(f"TOKEN_METADATA_PUBLIC_KEY={key}")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"TOKEN_METADATA_PUBLIC_KEY_BYTES={expected}")

    def test_invalid_points_stop_the_build(self):
        keys = [
            "04" + "00" * 64,
            ISSUER[:-1] + "0",  # one changed coordinate nibble
            "04" + f"{P256_P:064x}" + ISSUER[66:],
            ISSUER[:66] + f"{P256_P:064x}",
        ]
        for key in keys:
            with self.subTest(key=key):
                result = self.build_config(f"TOKEN_METADATA_PUBLIC_KEY={key}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("valid P-256 point", result.stderr)

    def test_invalid_encodings_stop_the_build(self):
        for key in ("04", ISSUER + "00", "0x" + ISSUER, "02" + ISSUER[2:], ISSUER[:-1] + "g", "'"):
            with self.subTest(key=key):
                result = self.build_config(f"TOKEN_METADATA_PUBLIC_KEY={key}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("TOKEN_METADATA_PUBLIC_KEY", result.stderr)

    def test_test_issuer_cannot_be_selected_as_production(self):
        for key in (TEST_ISSUER, TEST_ISSUER.upper()):
            with self.subTest(key=key):
                result = self.build_config(f"TOKEN_METADATA_PUBLIC_KEY={key}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("public test authority", result.stderr)

    def test_test_mode_requires_debug_and_excludes_production_key(self):
        result = self.build_config("TOKEN_METADATA_TEST_KEY=1", "DEBUG=0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires DEBUG=1", result.stderr)
        result = self.build_config("TOKEN_METADATA_TEST_KEY=1", "DEBUG=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "TOKEN_METADATA_TEST_KEY")
        result = self.build_config("TOKEN_METADATA_TEST_KEY=1", "DEBUG=1",
                                   f"TOKEN_METADATA_PUBLIC_KEY={ISSUER}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Select either", result.stderr)

    def test_no_issuer_is_supported(self):
        result = self.build_config()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
