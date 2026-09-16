#!/usr/bin/env python3
"""Offline M69 fixture smoke; it can never produce a live provider PASS."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SmokeError(RuntimeError):
    pass


def run(arguments: list[str], *, cwd: pathlib.Path, expect_success: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        arguments, cwd=cwd, capture_output=True, check=False,
        env={**os.environ, "CGO_ENABLED": "0"}, timeout=120,
    )
    if (completed.returncode == 0) != expect_success:
        raise SmokeError("push qualification fixture command returned an unexpected status")
    return completed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=pathlib.Path, required=True)
    parser.add_argument("--go", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    project = arguments.project.resolve(strict=True)
    gateway = project / "gateway"
    go = arguments.go.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="xz-push-qualification-") as raw:
        temporary = pathlib.Path(raw)
        fixture_binary = temporary / "fixture"
        validator_binary = temporary / "validator"
        run([str(go), "build", "-trimpath", "-o", str(fixture_binary),
             "./cmd/generatepushqualificationfixture"], cwd=gateway)
        run([str(go), "build", "-trimpath", "-o", str(validator_binary),
             "./cmd/validatepushqualification"], cwd=gateway)

        private = Ed25519PrivateKey.generate()
        private_path = temporary / "approval-private.pem"
        public_path = temporary / "approval-public.pem"
        private_path.write_bytes(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        public_path.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        private_path.chmod(0o600)
        public_path.chmod(0o644)
        receipt_path = temporary / "fixture-receipt.json"
        run([
            str(fixture_binary), "--qualification-id", "m69-smoke-1",
            "--signing-private-key", str(private_path),
            "--signing-key-id", "m69-smoke-key", "--output", str(receipt_path),
        ], cwd=gateway)
        receipt_data = receipt_path.read_bytes()
        receipt = json.loads(receipt_data)
        if receipt["result"] != "FIXTURE_PROTOCOL_PASS" or not receipt["development_only"]:
            raise SmokeError("fixture overstated live provider evidence")
        for forbidden in (b"fcm-fixture-token", b"m69-invalid", b"PRIVATE KEY", b"access_token"):
            if forbidden in receipt_data:
                raise SmokeError("fixture receipt contains provider or credential material")
        common = [
            str(validator_binary), "--receipt", str(receipt_path),
            "--trusted-public-key", str(public_path),
            "--expected-signing-key-id", "m69-smoke-key",
            "--expected-qualification-id", "m69-smoke-1",
            "--expected-environment", "staging",
            "--expected-config-sha256", receipt["config_sha256"],
            "--expected-tool-sha256", receipt["qualification_tool_sha256"],
        ]
        run(common, cwd=gateway)
        run([*common, "--require-live"], cwd=gateway, expect_success=False)

        tampered_path = temporary / "tampered-receipt.json"
        tampered_path.write_bytes(receipt_data.replace(
            b"FIXTURE_PROTOCOL_PASS", b"LIVE_PROVIDER_API_PASS"))
        tampered_path.chmod(0o444)
        tampered = list(common)
        tampered[tampered.index(str(receipt_path))] = str(tampered_path)
        run(tampered, cwd=gateway, expect_success=False)
    print("M69 push provider qualification fixture smoke: PASS (fixture only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

