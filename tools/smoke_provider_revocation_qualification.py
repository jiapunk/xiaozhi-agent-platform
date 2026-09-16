#!/usr/bin/env python3
"""Offline M72 chain; it can never produce live credential-revocation evidence."""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import pathlib
import subprocess
import sys
import tempfile

from smoke_app_delivery_qualification import canonical, key_pair, sha256


class SmokeError(RuntimeError):
    pass


def run(arguments: list[str], *, cwd: pathlib.Path,
        expect_success: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        arguments, cwd=cwd, capture_output=True, check=False,
        env={**os.environ, "CGO_ENABLED": "0"}, timeout=180,
    )
    if (completed.returncode == 0) != expect_success:
        raise SmokeError("M72 fixture command returned an unexpected status")
    return completed


def timestamp(value: datetime.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=pathlib.Path, required=True)
    parser.add_argument("--go", type=pathlib.Path, required=True)
    parser.add_argument("--workspace", type=pathlib.Path,
                        help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    project = arguments.project.resolve(strict=True)
    gateway = project / "gateway"
    go = arguments.go.resolve(strict=True)
    if arguments.workspace is None:
        workspace = tempfile.TemporaryDirectory(
            prefix="xz-provider-revocation-qualification-")
    else:
        arguments.workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
        workspace = contextlib.nullcontext(str(arguments.workspace.resolve()))
    with workspace as raw:
        temporary = pathlib.Path(raw)
        m71 = temporary / "m71"
        run([
            sys.executable,
            str(project / "tools" / "smoke_mtls_dispatch_qualification.py"),
            "--project", str(project), "--go", str(go),
            "--workspace", str(m71),
        ], cwd=project)

        binaries = {
            "attestation": "./cmd/signproviderrevocationattestation",
            "builder": "./cmd/buildproviderrevocationqualification",
            "validator": "./cmd/validateproviderrevocationqualification",
        }
        for name, package in binaries.items():
            run([str(go), "build", "-trimpath", "-o", str(temporary / name),
                 package], cwd=gateway)
        audit_private, audit_public = key_pair(temporary, "audit")
        final_private, final_public = key_pair(temporary, "final")

        provider_receipt = m71 / "provider-receipt.json"
        provider_document = json.loads(provider_receipt.read_bytes())
        m71_receipt = m71 / "m71-receipt.json"
        m71_document = json.loads(m71_receipt.read_bytes())
        m71_evaluated = datetime.datetime.fromisoformat(
            m71_document["evaluated_at"].replace("Z", "+00:00"))
        change_started_value = m71_evaluated + datetime.timedelta(seconds=1)
        change_completed_value = change_started_value + datetime.timedelta(seconds=1)
        observation_started_value = change_completed_value + datetime.timedelta(seconds=1)
        observation_finished_value = observation_started_value + datetime.timedelta(seconds=1)
        audit_verified_value = observation_finished_value + datetime.timedelta(seconds=1)
        evaluated_value = audit_verified_value + datetime.timedelta(seconds=1)

        provider = provider_document["providers"][0]
        observation_document = {
            "schema": 1,
            "qualification_id": "m71-smoke-1",
            "environment": "staging",
            "development_only": True,
            "config_sha256": "a" * 64,
            "qualification_tool_sha256": "b" * 64,
            "providers": [{
                "platform": provider["platform"],
                "application_id": provider["application_id"],
                "revoked_credential_id": provider["current_credential_id"],
                "active_credential_id": provider["next_credential_id"],
                "revoked_public_key_sha256": "c" * 64,
                "active_public_key_sha256": "d" * 64,
                "active_before_accepted": True,
                "revoked_credential_rejected": True,
                "active_after_accepted": True,
                "rejection_class": "apns-invalid-provider-token",
                "active_before_latency_ms": 10,
                "revoked_rejection_latency_ms": 11,
                "active_after_latency_ms": 12,
            }],
            "started_at": timestamp(observation_started_value),
            "finished_at": timestamp(observation_finished_value),
            "secret_free": True,
        }
        observation = temporary / "observation.json"
        observation.write_bytes(canonical(observation_document))
        observation.chmod(0o444)
        audit_evidence = temporary / "provider-audit-evidence.json"
        audit_evidence.write_bytes(
            b'{"fixture":true,"provider_console_access":false}\n')
        audit_evidence.chmod(0o444)
        audit_sha = sha256(audit_evidence.read_bytes())
        attestation = temporary / "attestation.json"
        run([
            str(temporary / "attestation"),
            "--observation", str(observation),
            "--provider-audit-evidence", str(audit_evidence),
            "--attestation-provider", "fixture",
            "--revocation-change-started-at", timestamp(change_started_value),
            "--revocation-change-completed-at", timestamp(change_completed_value),
            "--verified-at", timestamp(audit_verified_value),
            "--expires-at", timestamp(audit_verified_value + datetime.timedelta(hours=1)),
            "--signing-private-key", str(audit_private),
            "--signing-key-id", "m72-audit-fixture-key",
            "--output", str(attestation),
        ], cwd=gateway)

        app_receipt = m71 / "app-delivery-receipt.json"
        app_document = json.loads(app_receipt.read_bytes())
        vendor_sha = sha256((m71 / "vendor-evidence.json").read_bytes())
        workload_sha = sha256((m71 / "workload-evidence.json").read_bytes())
        manifest_document = {
            "schema": 1,
            "qualification_id": "m71-smoke-1",
            "environment": "staging",
            "deployment_id": "m71-pilot",
            "oci_release_id": "oci-release-1",
            "evaluation_time": timestamp(evaluated_value),
            "mtls_dispatch_evaluation_time": m71_document["evaluated_at"],
            "app_delivery_evaluation_time": app_document["evaluated_at"],
            "observation_path": str(observation),
            "revocation_attestation_path": str(attestation),
            "revocation_attestation_public_key_path": str(audit_public),
            "expected_revocation_attestation_key_id": "m72-audit-fixture-key",
            "expected_revocation_attestation_provider": "fixture",
            "expected_provider_audit_evidence_sha256": audit_sha,
            "mtls_dispatch_receipt_path": str(m71_receipt),
            "mtls_dispatch_public_key_path": str(m71 / "final-public.pem"),
            "expected_mtls_dispatch_key_id": "m71-final-fixture-key",
            "mtls_dispatch_observation_path": str(m71 / "dispatch-observation.json"),
            "app_delivery_receipt_path": str(app_receipt),
            "app_delivery_public_key_path": str(m71 / "app-final-public.pem"),
            "expected_app_delivery_key_id": "m71-app-final-fixture-key",
            "app_observation_path": str(m71 / "app-observation.json"),
            "provider_qualification_receipt_path": str(provider_receipt),
            "provider_qualification_public_key_path": str(m71 / "provider-public.pem"),
            "expected_provider_qualification_key_id": "m71-provider-fixture-key",
            "expected_provider_qualification_config_sha256": provider_document["config_sha256"],
            "expected_provider_qualification_tool_sha256": provider_document["qualification_tool_sha256"],
            "app_attestation_receipt_path": str(m71 / "app-attestation-receipt.json"),
            "app_attestation_public_key_path": str(m71 / "app-attestation-public.pem"),
            "expected_app_attestation_key_id": "m71-app-attestation-fixture-key",
            "expected_app_attestation_provider": "fixture",
            "expected_vendor_evidence_sha256": vendor_sha,
            "expected_app_binary_sha256": "a" * 64,
            "deployment_attestation_receipt_path": str(m71 / "deployment-attestation.json"),
            "deployment_attestation_public_key_path": str(m71 / "deployment-public.pem"),
            "expected_deployment_attestation_key_id": "m71-deployment-fixture-key",
            "expected_deployment_attestation_provider": "fixture",
            "expected_workload_evidence_sha256": workload_sha,
        }
        manifest = temporary / "evidence-manifest.json"
        manifest.write_bytes(canonical(manifest_document))
        manifest.chmod(0o444)
        receipt = temporary / "receipt.json"
        run([
            str(temporary / "builder"), "--evidence-manifest", str(manifest),
            "--signing-private-key", str(final_private),
            "--signing-key-id", "m72-final-fixture-key",
            "--output", str(receipt),
        ], cwd=gateway)
        receipt_payload = receipt.read_bytes()
        receipt_document = json.loads(receipt_payload)
        expected_gates = [
            "end_to_end_mtls_dispatch", "managed_database_failover",
            "provider_credential_revocation", "signed_app_delivery_receipt",
        ]
        if (receipt_document["result"] !=
                "FIXTURE_PROVIDER_CREDENTIAL_REVOCATION_PASS" or
                not receipt_document["development_only"] or
                receipt_document["unresolved_production_gates"] != expected_gates or
                receipt_document["production_ready"]):
            raise SmokeError("M72 fixture overstated live revocation evidence")
        for forbidden in (b"PRIVATE KEY", b"access_token", b"provider_token",
                          b"valid_target", b"device_token", b"registration_token"):
            if forbidden in receipt_payload or forbidden in observation.read_bytes():
                raise SmokeError("M72 evidence contains credential or target material")

        common = [
            str(temporary / "validator"), "--receipt", str(receipt),
            "--trusted-public-key", str(final_public),
            "--expected-signing-key-id", "m72-final-fixture-key",
            "--evidence-manifest", str(manifest),
        ]
        run(common, cwd=gateway)
        run([*common, "--require-live"], cwd=gateway, expect_success=False)

        tampered = temporary / "tampered-receipt.json"
        tampered.write_bytes(receipt_payload.replace(
            b"FIXTURE_PROVIDER_CREDENTIAL_REVOCATION_PASS",
            b"LIVE_PROVIDER_CREDENTIAL_REVOCATION_PASS"))
        tampered.chmod(0o444)
        tampered_common = list(common)
        tampered_common[tampered_common.index(str(receipt))] = str(tampered)
        run(tampered_common, cwd=gateway, expect_success=False)

        wrong_manifest_document = dict(manifest_document)
        wrong_manifest_document["expected_provider_audit_evidence_sha256"] = "f" * 64
        wrong_manifest = temporary / "wrong-manifest.json"
        wrong_manifest.write_bytes(canonical(wrong_manifest_document))
        wrong_manifest.chmod(0o444)
        wrong_common = list(common)
        wrong_common[wrong_common.index(str(manifest))] = str(wrong_manifest)
        run(wrong_common, cwd=gateway, expect_success=False)
    print("M72 provider credential revocation fixture smoke: PASS (fixture only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
