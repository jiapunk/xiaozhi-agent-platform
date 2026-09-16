#!/usr/bin/env python3
"""Offline M70 fixture chain; it can never produce a live signed-App PASS."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SmokeError(RuntimeError):
    pass


def run(arguments: list[str], *, cwd: pathlib.Path,
        expect_success: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        arguments, cwd=cwd, capture_output=True, check=False,
        env={**os.environ, "CGO_ENABLED": "0"}, timeout=120,
    )
    if (completed.returncode == 0) != expect_success:
        raise SmokeError("M70 fixture command returned an unexpected status")
    return completed


def key_pair(directory: pathlib.Path, name: str) -> tuple[pathlib.Path, pathlib.Path]:
    private = Ed25519PrivateKey.generate()
    private_path = directory / f"{name}-private.pem"
    public_path = directory / f"{name}-public.pem"
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
    return private_path, public_path


def canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=pathlib.Path, required=True)
    parser.add_argument("--go", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    project = arguments.project.resolve(strict=True)
    gateway = project / "gateway"
    go = arguments.go.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="xz-app-delivery-qualification-") as raw:
        temporary = pathlib.Path(raw)
        binaries = {
            "provider": "./cmd/generatepushqualificationfixture",
            "attestation": "./cmd/signappdeliveryattestation",
            "builder": "./cmd/buildappdeliveryqualification",
            "validator": "./cmd/validateappdeliveryqualification",
        }
        for name, package in binaries.items():
            run([str(go), "build", "-trimpath", "-o", str(temporary / name),
                 package], cwd=gateway)

        provider_private, provider_public = key_pair(temporary, "provider")
        attestation_private, attestation_public = key_pair(temporary, "attestation")
        final_private, final_public = key_pair(temporary, "final")
        provider_receipt = temporary / "provider-receipt.json"
        run([
            str(temporary / "provider"), "--qualification-id", "m70-smoke-1",
            "--signing-private-key", str(provider_private),
            "--signing-key-id", "m70-provider-fixture-key",
            "--output", str(provider_receipt),
        ], cwd=gateway)
        provider_payload = provider_receipt.read_bytes()
        provider_document = json.loads(provider_payload)

        provider_started = datetime.datetime.fromisoformat(
            provider_document["started_at"].replace("Z", "+00:00")
        )
        wake_ms = int(provider_started.timestamp() * 1000)
        verified_at_value = provider_started + datetime.timedelta(seconds=2)
        expires_at_value = verified_at_value + datetime.timedelta(hours=1)
        verified_at = verified_at_value.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_at = expires_at_value.strftime("%Y-%m-%dT%H:%M:%SZ")

        app_binary_sha = "a" * 64
        observation_document = {
            "schema": 1,
            "qualification_id": "m70-smoke-1",
            "qualification_nonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "environment": "staging",
            "development_only": True,
            "platform": "ios",
            "application_id": "com.example.product",
            "app_build_id": "ios-fixture-1",
            "app_binary_sha256": app_binary_sha,
            "wake_contract": "xz-action-consent-wake-v1",
            "content_free_wake": True,
            "background_network_request": False,
            "background_wake_count": 1,
            "wake_received_at_unix_ms": wake_ms,
            "foreground_entered_at_unix_ms": wake_ms + 1000,
            "authenticated_fetch_presented_at_unix_ms": wake_ms + 1200,
            "wake_to_fetch_ms": 1200,
            "challenge_binding_sha256": "b" * 64,
            "device_binding_sha256": "c" * 64,
            "decision_issued": False,
        }
        observation = temporary / "observation.json"
        observation.write_bytes(canonical(observation_document))
        observation.chmod(0o444)
        vendor_evidence = temporary / "vendor-evidence.json"
        vendor_evidence.write_bytes(b'{"fixture":true}\n')
        vendor_evidence.chmod(0o444)
        vendor_sha = sha256(vendor_evidence.read_bytes())
        attestation_receipt = temporary / "attestation-receipt.json"
        run([
            str(temporary / "attestation"),
            "--observation", str(observation),
            "--provider-receipt", str(provider_receipt),
            "--vendor-evidence", str(vendor_evidence),
            "--attested-key-sha256", "d" * 64,
            "--attestation-provider", "fixture",
            "--verified-at", verified_at,
            "--expires-at", expires_at,
            "--signing-private-key", str(attestation_private),
            "--signing-key-id", "m70-attestation-fixture-key",
            "--output", str(attestation_receipt),
        ], cwd=gateway)

        evaluation_time = verified_at
        receipt = temporary / "m70-receipt.json"
        evidence_arguments = [
            "--observation", str(observation),
            "--provider-receipt", str(provider_receipt),
            "--provider-trusted-public-key", str(provider_public),
            "--expected-provider-signing-key-id", "m70-provider-fixture-key",
            "--expected-provider-config-sha256", provider_document["config_sha256"],
            "--expected-provider-tool-sha256", provider_document["qualification_tool_sha256"],
            "--app-attestation-receipt", str(attestation_receipt),
            "--app-attestation-trusted-public-key", str(attestation_public),
            "--expected-app-attestation-signing-key-id", "m70-attestation-fixture-key",
            "--expected-app-attestation-provider", "fixture",
            "--expected-vendor-evidence-sha256", vendor_sha,
            "--expected-qualification-id", "m70-smoke-1",
            "--expected-environment", "staging",
            "--evaluation-time", evaluation_time,
        ]
        run([
            str(temporary / "builder"), *evidence_arguments,
            "--signing-private-key", str(final_private),
            "--signing-key-id", "m70-final-fixture-key",
            "--output", str(receipt),
        ], cwd=gateway)
        receipt_payload = receipt.read_bytes()
        receipt_document = json.loads(receipt_payload)
        if receipt_document["result"] != "FIXTURE_APP_FLOW_PASS" or not receipt_document["development_only"]:
            raise SmokeError("M70 fixture overstated live signed-App evidence")
        expected_fixture_gates = [
            "end_to_end_mtls_dispatch",
            "managed_database_failover",
            "provider_credential_revocation",
            "signed_app_delivery_receipt",
        ]
        if receipt_document["unresolved_production_gates"] != expected_fixture_gates:
            raise SmokeError("M70 fixture removed a production gate")
        for forbidden in (b"xz-device", b"AAECAw", b"indicator", b"access_token", b"PRIVATE KEY"):
            if forbidden in receipt_payload or forbidden in observation.read_bytes():
                raise SmokeError("M70 evidence contains action, identity or credential material")

        common = [
            str(temporary / "validator"),
            "--receipt", str(receipt),
            "--trusted-public-key", str(final_public),
            "--expected-signing-key-id", "m70-final-fixture-key",
            *evidence_arguments,
            "--expected-app-binary-sha256", app_binary_sha,
        ]
        run(common, cwd=gateway)
        run([*common, "--require-live"], cwd=gateway, expect_success=False)

        tampered_receipt = temporary / "tampered-receipt.json"
        tampered_receipt.write_bytes(receipt_payload.replace(
            b"FIXTURE_APP_FLOW_PASS", b"LIVE_SIGNED_APP_FLOW_PASS"))
        tampered_receipt.chmod(0o444)
        tampered_common = list(common)
        tampered_common[tampered_common.index(str(receipt))] = str(tampered_receipt)
        run(tampered_common, cwd=gateway, expect_success=False)

        tampered_observation = temporary / "tampered-observation.json"
        observation_document["background_wake_count"] = 2
        tampered_observation.write_bytes(canonical(observation_document))
        tampered_observation.chmod(0o444)
        subject_mix = list(common)
        subject_mix[subject_mix.index(str(observation))] = str(tampered_observation)
        run(subject_mix, cwd=gateway, expect_success=False)
    print("M70 signed-App delivery qualification fixture smoke: PASS (fixture only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
