"""SDK-free response decoding tests; no emulator or external Python packages."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from application_client.app_configuration import AppConfiguration


class AppConfigurationTests(unittest.TestCase):
    def test_all_settings_combinations(self):
        for flags in range(8):
            config = AppConfiguration.from_bytes(bytes([1, flags, 23, 45, 67]))
            self.assertEqual(config.flags, flags)
            self.assertEqual(config.version, (23, 45, 67))
            self.assertEqual(config.blind_signing_enabled, bool(flags & 1))
            self.assertEqual(config.display_nonce, bool(flags & 2))
            self.assertEqual(config.display_tx_hash, bool(flags & 4))

    def test_unknown_flags_are_preserved(self):
        config = AppConfiguration.from_bytes(bytes([1, 0xf8, 1, 2, 3]))
        self.assertEqual(config.flags, 0xf8)
        self.assertFalse(config.blind_signing_enabled)
        self.assertFalse(config.display_nonce)
        self.assertFalse(config.display_tx_hash)

    def test_bad_length_is_rejected(self):
        # Keep the format valid so rejecting six bytes depends on the length check.
        valid = bytes([1, 0, 1, 2, 3])
        for response in tuple(valid[:size] for size in range(5)) + (valid + b"\0",):
            with self.subTest(response=response), self.assertRaises(ValueError):
                AppConfiguration.from_bytes(response)

    def test_bad_format_is_rejected(self):
        for version in (0, 2, 255):
            response = bytes([version, 0, 1, 2, 3])
            with self.subTest(response=response), self.assertRaises(ValueError):
                AppConfiguration.from_bytes(response)


if __name__ == "__main__":
    unittest.main()
