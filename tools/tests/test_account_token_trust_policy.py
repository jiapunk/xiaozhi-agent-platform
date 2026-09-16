import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class AccountTokenTrustPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_production_uses_public_key_verification_only(self):
        config = self.read("gateway/internal/controlplane/config.go")
        command = self.read("gateway/cmd/controlplane/main.go")
        self.assertIn("APP_TOKEN_ED25519_KEYRING", config)
        self.assertIn("APP_TOKEN_ISSUER", config)
        self.assertIn("production Companion tokens require an Ed25519", config)
        self.assertIn("auth.NewCompanionJWTVerifier(", command)
        self.assertNotIn("NewCompanionJWTIssuer", command)

    def test_jwt_contract_is_algorithm_key_issuer_and_audience_bound(self):
        jwt = self.read("gateway/internal/auth/companion_jwt.go")
        for contract in (
            'header.Algorithm != "EdDSA"',
            'header.Type != "JWT"',
            "verifier.keys[header.KeyID]",
            "claims.Issuer != verifier.issuer",
            "claims.Audience != CompanionAudience",
            "!ValidIdentifier(claims.TenantID, 128)",
            "!ValidIdentifier(claims.TokenID, 128)",
        ):
            self.assertIn(contract, jwt)

    def test_jwt_json_and_base64_parsing_are_strict(self):
        jwt = self.read("gateway/internal/auth/companion_jwt.go")
        self.assertIn("decodeCanonicalBase64URL", jwt)
        self.assertIn("DisallowUnknownFields", jwt)
        self.assertIn("keys[key]", jwt)
        self.assertIn("keyDecoder.Decode(&keyTrailing)", jwt)

    def test_account_private_key_is_confined_to_issuer_library(self):
        issuer = self.read("gateway/internal/auth/companion_jwt.go")
        command = self.read("gateway/cmd/controlplane/main.go")
        self.assertIn("type CompanionJWTIssuer struct", issuer)
        self.assertIn("ed25519.Sign(issuer.privateKey", issuer)
        self.assertNotIn("ed25519.PrivateKey", command)
        self.assertNotIn("ed25519.Sign", command)

    def test_hmac_companion_mode_remains_development_only(self):
        config = self.read("gateway/internal/controlplane/config.go")
        self.assertIn("if !settings.AllowInsecure", config)
        self.assertIn("production Companion tokens require", config)
        self.assertIn("exactly one Companion token keyring", config)

    def test_claim_server_accepts_verifier_interface_not_signing_secret(self):
        auth = self.read("gateway/internal/auth/token.go")
        server = self.read("gateway/internal/controlplane/server.go")
        self.assertIn("type AuthorizationVerifier interface", auth)
        self.assertIn("AppVerifier", server)
        self.assertIn("auth.AuthorizationVerifier", server)
        self.assertIn("server.config.AppVerifier.VerifyAuthorization", server)

    def test_end_to_end_test_rejects_legacy_hmac_under_jwt_configuration(self):
        test = self.read("gateway/internal/controlplane/server_test.go")
        self.assertIn(
            "TestDeviceClaimAcceptsOnlyConfiguredAsymmetricAccountIssuer",
            test,
        )
        self.assertIn("legacy HMAC account token status", test)


if __name__ == "__main__":
    unittest.main()
