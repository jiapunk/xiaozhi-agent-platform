from __future__ import annotations

import base64
import hashlib
import hmac
import os
import tempfile
import unittest
from pathlib import Path

import validate_generation_state as validator


KEY = b"generation-state-key-0123456789abcdef012"
NOW = 1_800_000_000
GENESIS = {
    "generation_id": "staging",
    "generation_sequence": 0,
    "receipt_sha256": "a" * 64,
}
REPLICAS = [
    {"replica_id": "controlplane-a", "role": "controlplane"},
    {"replica_id": "firmwareorigin-a", "role": "firmwareorigin"},
]


def signed_state(**overrides: object) -> tuple[dict[str, object], bytes, str]:
    state: dict[str, object] = {
        "schema": 1,
        "revision": 1,
        "previous_record_sha256": "0" * 64,
        "phase": "STABLE",
        "active": GENESIS,
        "pending": None,
        "required_replicas": REPLICAS,
        "acknowledgements": [],
        "prepare_deadline": 0,
        "drain_until": 0,
        "commit_deadline": 0,
        "updated_at": NOW,
    }
    state.update(overrides)
    signature = hmac.new(KEY, validator._canonical(state)[:-1], hashlib.sha256).digest()
    state["record_hmac_b64url"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    payload = validator._canonical(state)
    return state, payload, hashlib.sha256(payload).hexdigest()


def write_file(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o400)


class GenerationStateValidatorTests(unittest.TestCase):
    def make_state(self) -> tuple[tempfile.TemporaryDirectory[str], Path, bytes]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "state"
        root.mkdir(mode=0o700)
        _, payload, digest = signed_state()
        write_file(root / "state-00000000000000000001.json", payload)
        current = validator._canonical({"revision": 1, "record_sha256": digest})
        write_file(root / "CURRENT", current)
        return temporary, root, payload

    def test_valid_genesis(self) -> None:
        temporary, root, _ = self.make_state()
        self.addCleanup(temporary.cleanup)
        state, digest = validator.validate(root, KEY)
        self.assertEqual(state["active"], GENESIS)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_tampered_record_fails(self) -> None:
        temporary, root, payload = self.make_state()
        self.addCleanup(temporary.cleanup)
        record = root / "state-00000000000000000001.json"
        record.chmod(0o600)
        record.write_bytes(payload.replace(b'"STABLE"', b'"stable"'))
        record.chmod(0o400)
        with self.assertRaises(validator.StateError):
            validator.validate(root, KEY)

    def test_stale_current_fails(self) -> None:
        temporary, root, _ = self.make_state()
        self.addCleanup(temporary.cleanup)
        current = root / "CURRENT"
        current.chmod(0o600)
        current.write_bytes(validator._canonical({"revision": 1, "record_sha256": "f" * 64}))
        current.chmod(0o400)
        with self.assertRaises(validator.StateError):
            validator.validate(root, KEY)

    def test_valid_hmac_cannot_authorize_invalid_transition(self) -> None:
        temporary, root, first_payload = self.make_state()
        self.addCleanup(temporary.cleanup)
        first_digest = hashlib.sha256(first_payload).hexdigest()
        _, second_payload, second_digest = signed_state(
            revision=2, previous_record_sha256=first_digest, updated_at=NOW + 1
        )
        write_file(root / "state-00000000000000000002.json", second_payload)
        current = root / "CURRENT"
        current.chmod(0o600)
        current.write_bytes(validator._canonical({"revision": 2, "record_sha256": second_digest}))
        current.chmod(0o400)
        with self.assertRaises(validator.StateError):
            validator.validate(root, KEY)

    def test_key_parser_is_canonical_and_bounded(self) -> None:
        prior = os.environ.get("GENERATION_STATE_HMAC_KEY_B64")
        self.addCleanup(self._restore_key, prior)
        os.environ["GENERATION_STATE_HMAC_KEY_B64"] = base64.urlsafe_b64encode(KEY).rstrip(b"=").decode()
        self.assertEqual(validator._key(), KEY)
        os.environ["GENERATION_STATE_HMAC_KEY_B64"] = "d2Vhaw"
        with self.assertRaises(validator.StateError):
            validator._key()

    @staticmethod
    def _restore_key(value: str | None) -> None:
        if value is None:
            os.environ.pop("GENERATION_STATE_HMAC_KEY_B64", None)
        else:
            os.environ["GENERATION_STATE_HMAC_KEY_B64"] = value


if __name__ == "__main__":
    unittest.main()
