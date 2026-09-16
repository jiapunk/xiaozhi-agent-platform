#!/usr/bin/env python3
"""Offline M71 receipt chain; it can never produce a live mTLS PASS."""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import pathlib
import subprocess
import tempfile

from smoke_app_delivery_qualification import canonical, key_pair, sha256


class SmokeError(RuntimeError):
    pass


def run(arguments: list[str], *, cwd: pathlib.Path,
        expect_success: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        arguments, cwd=cwd, capture_output=True, check=False,
        env={**os.environ, "CGO_ENABLED": "0"}, timeout=120,
    )
    if (completed.returncode == 0) != expect_success:
        raise SmokeError("M71 fixture command returned an unexpected status")
    return completed


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
            prefix="xz-mtls-dispatch-qualification-")
    else:
        arguments.workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
        workspace = contextlib.nullcontext(str(arguments.workspace.resolve()))
    with workspace as raw:
        temporary = pathlib.Path(raw)
        binaries = {
            "provider": "./cmd/generatepushqualificationfixture",
            "app-attestation": "./cmd/signappdeliveryattestation",
            "app-builder": "./cmd/buildappdeliveryqualification",
            "deployment-attestation": "./cmd/signmtlsdispatchattestation",
            "builder": "./cmd/buildmtlsdispatchqualification",
            "validator": "./cmd/validatemtlsdispatchqualification",
        }
        for name, package in binaries.items():
            run([str(go), "build", "-trimpath", "-o", str(temporary / name),
                 package], cwd=gateway)

        provider_private, provider_public = key_pair(temporary, "provider")
        app_attestation_private, app_attestation_public = key_pair(
            temporary, "app-attestation")
        app_final_private, app_final_public = key_pair(temporary, "app-final")
        deployment_private, deployment_public = key_pair(temporary, "deployment")
        final_private, final_public = key_pair(temporary, "final")

        provider_receipt = temporary / "provider-receipt.json"
        run([
            str(temporary / "provider"), "--qualification-id", "m71-smoke-1",
            "--signing-private-key", str(provider_private),
            "--signing-key-id", "m71-provider-fixture-key",
            "--output", str(provider_receipt),
        ], cwd=gateway)
        provider_payload = provider_receipt.read_bytes()
        provider_document = json.loads(provider_payload)
        provider_started = datetime.datetime.fromisoformat(
            provider_document["started_at"].replace("Z", "+00:00")
        )
        wake_ms = int(provider_started.timestamp() * 1000)
        app_verified_value = provider_started + datetime.timedelta(seconds=2)
        deployment_verified_value = provider_started + datetime.timedelta(seconds=3)
        final_evaluated_value = provider_started + datetime.timedelta(seconds=4)
        app_verified = app_verified_value.strftime("%Y-%m-%dT%H:%M:%SZ")
        deployment_verified = deployment_verified_value.strftime("%Y-%m-%dT%H:%M:%SZ")
        app_expires = (app_verified_value + datetime.timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        deployment_expires = (
            deployment_verified_value + datetime.timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        final_evaluated = final_evaluated_value.strftime("%Y-%m-%dT%H:%M:%SZ")

        app_binary_sha = "a" * 64
        app_observation_document = {
            "schema": 1,
            "qualification_id": "m71-smoke-1",
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
        app_observation = temporary / "app-observation.json"
        app_observation.write_bytes(canonical(app_observation_document))
        app_observation.chmod(0o444)
        vendor_evidence = temporary / "vendor-evidence.json"
        vendor_evidence.write_bytes(b'{"fixture":true}\n')
        vendor_evidence.chmod(0o444)
        vendor_sha = sha256(vendor_evidence.read_bytes())
        app_attestation_receipt = temporary / "app-attestation-receipt.json"
        run([
            str(temporary / "app-attestation"),
            "--observation", str(app_observation),
            "--provider-receipt", str(provider_receipt),
            "--vendor-evidence", str(vendor_evidence),
            "--attested-key-sha256", "d" * 64,
            "--attestation-provider", "fixture",
            "--verified-at", app_verified,
            "--expires-at", app_expires,
            "--signing-private-key", str(app_attestation_private),
            "--signing-key-id", "m71-app-attestation-fixture-key",
            "--output", str(app_attestation_receipt),
        ], cwd=gateway)
        app_delivery_receipt = temporary / "app-delivery-receipt.json"
        m70_arguments = [
            "--observation", str(app_observation),
            "--provider-receipt", str(provider_receipt),
            "--provider-trusted-public-key", str(provider_public),
            "--expected-provider-signing-key-id", "m71-provider-fixture-key",
            "--expected-provider-config-sha256", provider_document["config_sha256"],
            "--expected-provider-tool-sha256",
            provider_document["qualification_tool_sha256"],
            "--app-attestation-receipt", str(app_attestation_receipt),
            "--app-attestation-trusted-public-key", str(app_attestation_public),
            "--expected-app-attestation-signing-key-id",
            "m71-app-attestation-fixture-key",
            "--expected-app-attestation-provider", "fixture",
            "--expected-vendor-evidence-sha256", vendor_sha,
            "--expected-qualification-id", "m71-smoke-1",
            "--expected-environment", "staging",
            "--evaluation-time", app_verified,
        ]
        run([
            str(temporary / "app-builder"), *m70_arguments,
            "--signing-private-key", str(app_final_private),
            "--signing-key-id", "m71-app-final-fixture-key",
            "--output", str(app_delivery_receipt),
        ], cwd=gateway)

        services = [
            "gateway", "controlplane", "agentproxy", "firmwareorigin",
            "generationcoordinator", "accountauthorization",
            "factorytimeauthority",
        ]
        dispatch_observation_document = {
            "schema": 1,
            "qualification_id": "m71-smoke-1",
            "environment": "staging",
            "development_only": True,
            "deployment_id": "m71-pilot",
            "oci_release_id": "oci-release-1",
            "services": services,
            "endpoint_authority_sha256": "0" * 64,
            "config_sha256": "1" * 64,
            "qualification_tool_sha256": "2" * 64,
            "kubernetes_deployment_receipt_sha256": "3" * 64,
            "kubernetes_admission_receipt_sha256": "4" * 64,
            "controlplane_pod_binding_sha256": "5" * 64,
            "current_client_certificate_sha256": "6" * 64,
            "next_client_certificate_sha256": "7" * 64,
            "revoked_client_certificate_sha256": "8" * 64,
            "server_leaf_certificate_sha256": "9" * 64,
            "tls_version": "TLS1.3",
            "negotiated_protocol": "h2",
            "wake_contract": "xz-private-wake-dispatch-v1",
            "current_credential_accepted": True,
            "next_credential_accepted": True,
            "anonymous_client_rejected": True,
            "revoked_client_rejected": True,
            "wrong_server_name_rejected": True,
            "current_latency_ms": 10,
            "next_latency_ms": 11,
            "started_at": provider_started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at": (
                provider_started + datetime.timedelta(seconds=1)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "secret_free": True,
        }
        dispatch_observation = temporary / "dispatch-observation.json"
        dispatch_observation.write_bytes(canonical(dispatch_observation_document))
        dispatch_observation.chmod(0o444)
        workload_evidence = temporary / "workload-evidence.json"
        workload_evidence.write_bytes(b'{"fixture":true,"services":7}\n')
        workload_evidence.chmod(0o444)
        workload_sha = sha256(workload_evidence.read_bytes())
        deployment_attestation = temporary / "deployment-attestation.json"
        run([
            str(temporary / "deployment-attestation"),
            "--observation", str(dispatch_observation),
            "--workload-evidence", str(workload_evidence),
            "--attestation-provider", "fixture",
            "--verified-at", deployment_verified,
            "--expires-at", deployment_expires,
            "--signing-private-key", str(deployment_private),
            "--signing-key-id", "m71-deployment-fixture-key",
            "--output", str(deployment_attestation),
        ], cwd=gateway)

        receipt = temporary / "m71-receipt.json"
        evidence_arguments = [
            "--observation", str(dispatch_observation),
            "--app-delivery-receipt", str(app_delivery_receipt),
            "--app-delivery-trusted-public-key", str(app_final_public),
            "--expected-app-delivery-signing-key-id", "m71-app-final-fixture-key",
            "--app-observation", str(app_observation),
            "--provider-receipt", str(provider_receipt),
            "--provider-trusted-public-key", str(provider_public),
            "--expected-provider-signing-key-id", "m71-provider-fixture-key",
            "--expected-provider-config-sha256", provider_document["config_sha256"],
            "--expected-provider-tool-sha256",
            provider_document["qualification_tool_sha256"],
            "--app-attestation-receipt", str(app_attestation_receipt),
            "--app-attestation-trusted-public-key", str(app_attestation_public),
            "--expected-app-attestation-signing-key-id",
            "m71-app-attestation-fixture-key",
            "--expected-app-attestation-provider", "fixture",
            "--expected-vendor-evidence-sha256", vendor_sha,
            "--expected-app-binary-sha256", app_binary_sha,
            "--app-evaluation-time", app_verified,
            "--deployment-attestation-receipt", str(deployment_attestation),
            "--deployment-attestation-trusted-public-key", str(deployment_public),
            "--expected-deployment-attestation-signing-key-id",
            "m71-deployment-fixture-key",
            "--expected-deployment-attestation-provider", "fixture",
            "--expected-workload-evidence-sha256", workload_sha,
            "--expected-qualification-id", "m71-smoke-1",
            "--expected-environment", "staging",
            "--expected-deployment-id", "m71-pilot",
            "--expected-oci-release-id", "oci-release-1",
            "--evaluation-time", final_evaluated,
        ]
        run([
            str(temporary / "builder"), *evidence_arguments,
            "--signing-private-key", str(final_private),
            "--signing-key-id", "m71-final-fixture-key",
            "--output", str(receipt),
        ], cwd=gateway)
        receipt_payload = receipt.read_bytes()
        receipt_document = json.loads(receipt_payload)
        expected_gates = [
            "end_to_end_mtls_dispatch", "managed_database_failover",
            "provider_credential_revocation", "signed_app_delivery_receipt",
        ]
        if (receipt_document["result"] != "FIXTURE_MTLS_DISPATCH_PASS" or
                not receipt_document["development_only"] or
                receipt_document["unresolved_production_gates"] != expected_gates):
            raise SmokeError("M71 fixture overstated live mTLS evidence")
        for forbidden in (b"tenant-", b"device-", b"user-", b"PRIVATE KEY",
                          b"access_token", b"provider_token"):
            if forbidden in receipt_payload or forbidden in dispatch_observation.read_bytes():
                raise SmokeError("M71 evidence contains identity or credential material")

        common = [
            str(temporary / "validator"),
            "--receipt", str(receipt),
            "--trusted-public-key", str(final_public),
            "--expected-signing-key-id", "m71-final-fixture-key",
            *evidence_arguments,
        ]
        run(common, cwd=gateway)
        run([*common, "--require-live"], cwd=gateway, expect_success=False)

        tampered_receipt = temporary / "tampered-receipt.json"
        tampered_receipt.write_bytes(receipt_payload.replace(
            b"FIXTURE_MTLS_DISPATCH_PASS", b"LIVE_MTLS_DISPATCH_PASS"))
        tampered_receipt.chmod(0o444)
        tampered_common = list(common)
        tampered_common[tampered_common.index(str(receipt))] = str(tampered_receipt)
        run(tampered_common, cwd=gateway, expect_success=False)

        mixed_observation = temporary / "mixed-observation.json"
        dispatch_observation_document["deployment_id"] = "other-pilot"
        mixed_observation.write_bytes(canonical(dispatch_observation_document))
        mixed_observation.chmod(0o444)
        subject_mix = list(common)
        subject_mix[subject_mix.index(str(dispatch_observation))] = str(mixed_observation)
        run(subject_mix, cwd=gateway, expect_success=False)
    print("M71 mTLS dispatch qualification fixture smoke: PASS (fixture only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
