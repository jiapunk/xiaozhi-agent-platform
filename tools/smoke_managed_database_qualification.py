#!/usr/bin/env python3
"""Offline M73 chain; it can never produce live managed-database evidence."""

from __future__ import annotations

import argparse
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
        env={**os.environ, "CGO_ENABLED": "0"}, timeout=240,
    )
    if (completed.returncode == 0) != expect_success:
        raise SmokeError(
            "M73 fixture command returned an unexpected status: "
            + completed.stderr.decode("utf-8", errors="replace")[:500]
        )
    return completed


def timestamp(value: datetime.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=pathlib.Path, required=True)
    parser.add_argument("--go", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    project = arguments.project.resolve(strict=True)
    gateway = project / "gateway"
    go = arguments.go.resolve(strict=True)
    with tempfile.TemporaryDirectory(
            prefix="xz-managed-database-qualification-") as raw:
        temporary = pathlib.Path(raw)
        m72 = temporary / "m72"
        run([
            sys.executable,
            str(project / "tools" / "smoke_provider_revocation_qualification.py"),
            "--project", str(project), "--go", str(go),
            "--workspace", str(m72),
        ], cwd=project)

        binaries = {
            "attestation": "./cmd/signmanageddatabaseattestation",
            "builder": "./cmd/buildmanageddatabasequalification",
            "validator": "./cmd/validatemanageddatabasequalification",
        }
        for name, package in binaries.items():
            run([str(go), "build", "-trimpath", "-o", str(temporary / name),
                 package], cwd=gateway)
        audit_private, audit_public = key_pair(temporary, "database-audit")
        final_private, final_public = key_pair(temporary, "database-final")

        provider_receipt = m72 / "receipt.json"
        provider_document = json.loads(provider_receipt.read_bytes())
        provider_evaluated = datetime.datetime.fromisoformat(
            provider_document["evaluated_at"].replace("Z", "+00:00"))
        failover_started = provider_evaluated + datetime.timedelta(seconds=1)
        marker_time = failover_started + datetime.timedelta(seconds=1)
        exclusion_time = marker_time + datetime.timedelta(seconds=5)
        ready_time = exclusion_time + datetime.timedelta(seconds=1)
        failover_finished = ready_time + datetime.timedelta(seconds=2)
        restore_started = failover_finished + datetime.timedelta(seconds=1)
        restore_finished = restore_started + datetime.timedelta(seconds=1)
        attestation_verified = restore_finished + datetime.timedelta(seconds=1)
        evaluated = attestation_verified + datetime.timedelta(seconds=1)
        qualification_id = provider_document["qualification_id"]
        roles = ["ownership", "accountauthorization", "factorytimeauthority"]
        run_binding = "1" * 64
        failover_config = "2" * 64

        ready_document = {
            "schema": 1,
            "qualification_id": qualification_id,
            "run_binding_sha256": run_binding,
            "config_sha256": failover_config,
            "roles": roles,
            "ready_at": timestamp(ready_time),
        }
        ready_signal = temporary / "ready-signal.json"
        ready_signal.write_bytes(canonical(ready_document))
        ready_signal.chmod(0o444)

        failover_databases = []
        for index, role in enumerate(roles):
            failover_databases.append({
                "role": role,
                "managed_cluster_id": f"fixture-managed-cluster-{index + 1}",
                "endpoint_authority_sha256": f"{index + 3:x}" * 64,
                "before_node_binding_sha256": f"{index + 6:x}" * 64,
                "after_node_binding_sha256": f"{index + 9:x}" * 64,
                "before_postgres_version": 170006,
                "after_postgres_version": 170006,
                "product_schemas_verified": True,
                "failover_observed": True,
                "all_acknowledged_events_durable": True,
                "restore_marker_sequence": 2,
                "restore_marker_committed_at": timestamp(marker_time),
                "restore_exclusion_sequence": 3,
                "restore_exclusion_committed_at": timestamp(exclusion_time),
                "post_failover_sequence": 6,
                "post_failover_committed_at": timestamp(failover_finished),
                "acknowledged_event_count": 6,
                "ambiguous_commit_recovered_count": 1 if index == 0 else 0,
                "availability_failure_count": 1 if index == 0 else 0,
                "failover_detection_ms": 1000,
                "maximum_unavailable_ms": 500 if index == 0 else 0,
            })
        failover_document = {
            "schema": 1,
            "qualification_id": qualification_id,
            "environment": "staging",
            "development_only": True,
            "run_binding_sha256": run_binding,
            "config_sha256": failover_config,
            "qualification_tool_sha256": "a" * 64,
            "ready_signal_sha256": sha256(ready_signal.read_bytes()),
            "roles": roles,
            "databases": failover_databases,
            "ready_at": timestamp(ready_time),
            "started_at": timestamp(failover_started),
            "finished_at": timestamp(failover_finished),
            "secret_free": True,
        }
        failover_observation = temporary / "failover-observation.json"
        failover_observation.write_bytes(canonical(failover_document))
        failover_observation.chmod(0o444)
        failover_sha = sha256(failover_observation.read_bytes())

        restore_databases = []
        audit_databases = []
        recovery_target = marker_time + datetime.timedelta(seconds=2)
        for index, role in enumerate(roles):
            restore_operation = f"fixture-restore-operation-{index + 1}"
            cluster = f"fixture-managed-cluster-{index + 1}"
            restore_databases.append({
                "role": role,
                "managed_cluster_id": cluster,
                "restore_operation_id": restore_operation,
                "source_endpoint_authority_sha256": f"{index + 3:x}" * 64,
                "restore_endpoint_authority_sha256": f"{index + 12:x}" * 64,
                "restored_node_binding_sha256": f"{index + 6:x}" * 64,
                "restored_postgres_version": 170006,
                "requested_recovery_target": timestamp(recovery_target),
                "product_schemas_verified": True,
                "pre_restore_event_present": True,
                "restore_marker_present": True,
                "restore_exclusion_absent": True,
                "heartbeat_events_absent": True,
                "post_failover_event_absent": True,
                "restored_event_count": 2,
                "restore_marker_committed_at": timestamp(marker_time),
            })
            audit_databases.append({
                "role": role,
                "managed_cluster_id": cluster,
                "failover_operation_id": f"fixture-failover-operation-{index + 1}",
                "automated_backup_id": f"fixture-automated-backup-{index + 1}",
                "restore_operation_id": restore_operation,
                "requested_recovery_target": timestamp(recovery_target),
                "observed_rpo_seconds": 0,
                "failover_rto_seconds": 2,
                "restore_rto_seconds": 1,
            })
        restore_document = {
            "schema": 1,
            "qualification_id": qualification_id,
            "environment": "staging",
            "development_only": True,
            "run_binding_sha256": run_binding,
            "failover_observation_sha256": failover_sha,
            "config_sha256": "b" * 64,
            "qualification_tool_sha256": "c" * 64,
            "roles": roles,
            "databases": restore_databases,
            "started_at": timestamp(restore_started),
            "finished_at": timestamp(restore_finished),
            "secret_free": True,
        }
        restore_observation = temporary / "restore-observation.json"
        restore_observation.write_bytes(canonical(restore_document))
        restore_observation.chmod(0o444)

        audit_document = {
            "schema": 1,
            "qualification_id": qualification_id,
            "environment": "staging",
            "development_only": True,
            "provider": "fixture",
            "worm_record_id": "fixture-worm-record-1",
            "failover_started_at": timestamp(ready_time),
            "failover_completed_at": timestamp(failover_finished),
            "restore_completed_at": timestamp(restore_finished),
            "rpo_target_seconds": 300,
            "rto_target_seconds": 300,
            "databases": audit_databases,
            "managed_service_control_plane_verified": False,
            "failover_operator_event_verified": False,
            "automated_backups_verified": False,
            "point_in_time_restore_verified": False,
            "encryption_at_rest_verified": False,
            "restore_isolation_verified": False,
            "worm_retention_verified": False,
        }
        audit_evidence = temporary / "database-audit-evidence.json"
        audit_evidence.write_bytes(json.dumps(
            audit_document, indent=2, separators=(",", ": "),
        ).encode("utf-8") + b"\n")
        audit_evidence.chmod(0o444)
        attestation = temporary / "database-attestation.json"
        run([
            str(temporary / "attestation"),
            "--failover-observation", str(failover_observation),
            "--restore-observation", str(restore_observation),
            "--provider-audit-evidence", str(audit_evidence),
            "--verified-at", timestamp(attestation_verified),
            "--expires-at", timestamp(attestation_verified + datetime.timedelta(hours=1)),
            "--signing-private-key", str(audit_private),
            "--signing-key-id", "m73-database-audit-fixture-key",
            "--output", str(attestation),
        ], cwd=gateway)

        manifest_document = {
            "schema": 1,
            "qualification_id": qualification_id,
            "environment": "staging",
            "deployment_id": provider_document["deployment_id"],
            "oci_release_id": provider_document["oci_release_id"],
            "evaluation_time": timestamp(evaluated),
            "expected_run_binding_sha256": run_binding,
            "expected_failover_config_sha256": failover_config,
            "expected_failover_tool_sha256": "a" * 64,
            "expected_restore_config_sha256": "b" * 64,
            "expected_restore_tool_sha256": "c" * 64,
            "failover_observation_path": str(failover_observation),
            "ready_signal_path": str(ready_signal),
            "restore_observation_path": str(restore_observation),
            "database_attestation_path": str(attestation),
            "database_attestation_public_key_path": str(audit_public),
            "expected_database_attestation_key_id": "m73-database-audit-fixture-key",
            "expected_database_attestation_provider": "fixture",
            "expected_provider_audit_evidence_sha256": sha256(audit_evidence.read_bytes()),
            "provider_revocation_receipt_path": str(provider_receipt),
            "provider_revocation_public_key_path": str(m72 / "final-public.pem"),
            "expected_provider_revocation_key_id": "m72-final-fixture-key",
            "provider_revocation_evidence_manifest_path": str(m72 / "evidence-manifest.json"),
        }
        manifest = temporary / "evidence-manifest.json"
        manifest.write_bytes(canonical(manifest_document))
        manifest.chmod(0o444)
        receipt = temporary / "receipt.json"
        run([
            str(temporary / "builder"), "--evidence-manifest", str(manifest),
            "--signing-private-key", str(final_private),
            "--signing-key-id", "m73-final-fixture-key",
            "--output", str(receipt),
        ], cwd=gateway)
        receipt_payload = receipt.read_bytes()
        receipt_document = json.loads(receipt_payload)
        expected_gates = [
            "end_to_end_mtls_dispatch", "managed_database_failover",
            "provider_credential_revocation", "signed_app_delivery_receipt",
        ]
        if (receipt_document["result"] !=
                "FIXTURE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS" or
                not receipt_document["development_only"] or
                receipt_document["unresolved_production_gates"] != expected_gates or
                receipt_document["production_ready"]):
            raise SmokeError("M73 fixture overstated live database evidence")
        for forbidden in (b"postgresql://", b"password=", b"PRIVATE KEY",
                          b"access_token", b"device_token"):
            if forbidden in receipt_payload or forbidden in failover_observation.read_bytes():
                raise SmokeError("M73 public evidence contains secret material")

        common = [
            str(temporary / "validator"), "--receipt", str(receipt),
            "--trusted-public-key", str(final_public),
            "--expected-signing-key-id", "m73-final-fixture-key",
            "--evidence-manifest", str(manifest),
        ]
        run(common, cwd=gateway)
        run([*common, "--require-live"], cwd=gateway, expect_success=False)

        tampered = temporary / "tampered-receipt.json"
        tampered.write_bytes(receipt_payload.replace(
            b"FIXTURE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS",
            b"LIVE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS"))
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
    print("M73 managed database failover/restore fixture smoke: PASS (fixture only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
