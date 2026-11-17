"""Validate pinned deployment configuration through the real Makefile."""
import unittest
import test_token_metadata_key as key_tests


class StakingBuildTests(unittest.TestCase):
    setUp = key_tests.IssuerBuildTests.setUp
    build_config = key_tests.IssuerBuildTests.build_config

    def test_default_has_no_profile(self):
        result = self.build_config()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("HAVE_STAKING_DEPOSIT", result.stdout)

    def test_profile_binds_complete_chain_and_contract(self):
        for chain in (1, 2**256 - 1):
            result = self.build_config(f"STAKING_DEPOSIT_CHAIN_ID={chain}",
                                       "STAKING_DEPOSIT_CONTRACT=" + "aB" * 64)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = ",".join(f"0x{x:02x}" for x in chain.to_bytes(32, "big") + b"\xab" * 64)
            self.assertIn("HAVE_STAKING_DEPOSIT", result.stdout)
            self.assertIn("STAKING_DEPOSIT_PROFILE_BYTES=" + expected, result.stdout)

    def test_test_profile_gate(self):
        result = self.build_config("STAKING_DEPOSIT_TEST_PROFILE=1", "DEBUG=0")
        self.assertNotEqual(result.returncode, 0)
        result = self.build_config("STAKING_DEPOSIT_TEST_PROFILE=1", "DEBUG=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "HAVE_STAKING_DEPOSIT STAKING_DEPOSIT_TEST_PROFILE")
        result = self.build_config("STAKING_DEPOSIT_TEST_PROFILE=1", "DEBUG=1",
                                   "STAKING_DEPOSIT_CHAIN_ID=1", "STAKING_DEPOSIT_CONTRACT=" + "42" * 64)
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_profiles_fail_build(self):
        for chain, address in (("", "42" * 64), ("1", ""), ("0", "42" * 64),
                               (str(2**256), "42" * 64), ("'", "42" * 64),
                               ("1", "'"), ("1", "00" * 64), ("1", "42" * 63),
                               ("1", "Q" + "42" * 64), ("1", "gg" * 64)):
            with self.subTest(chain=chain, address=address):
                result = self.build_config(f"STAKING_DEPOSIT_CHAIN_ID={chain}",
                                           f"STAKING_DEPOSIT_CONTRACT={address}")
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
