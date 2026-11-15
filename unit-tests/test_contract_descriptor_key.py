"""Apply the issuer configuration contract to the independent contract authority."""
import unittest
import test_token_metadata_key as key_tests


class ContractIssuerBuildTests(key_tests.IssuerBuildTests):
    def build_config(self, *settings):
        result = super().build_config(*(s.replace("TOKEN_METADATA", "CONTRACT_DESCRIPTOR") for s in settings))
        result.stdout = result.stdout.replace("CONTRACT_DESCRIPTOR", "TOKEN_METADATA")
        result.stderr = result.stderr.replace("CONTRACT_DESCRIPTOR", "TOKEN_METADATA")
        return result

    def test_token_key_does_not_configure_contract_issuer(self):
        result = super().build_config(f"TOKEN_METADATA_PUBLIC_KEY={key_tests.ISSUER}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("CONTRACT_DESCRIPTOR_PUBLIC_KEY_BYTES", result.stdout)


if __name__ == "__main__":
    unittest.main()
