#!/usr/bin/env python3
"""TEST ONLY: bind an M58 plan to the current remote-signing evidence."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROJECT = Path(__file__).resolve().parents[1]
TOOLS = PROJECT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular  # noqa: E402
from sacrificial_provisioning_plan import (  # noqa: E402
    SacrificialPlanError,
    bind_release,
    build_request,
    canonical_json,
    load_release_evidence,
    require_active,
    verify_receipt,
)
import sacrificial_attempt_ledger as attempt_ledger  # noqa: E402
import sacrificial_trusted_time as trusted_time  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    args = parser.parse_args()
    try:
        signing_raw = read_regular(args.signing_request, 512 * 1024, "signing request")
        artifact_raw = read_regular(
            args.signed_artifact_verification,
            512 * 1024,
            "signed-artifact verification",
        )
        release = load_release_evidence(signing_raw, artifact_raw)
        with tempfile.TemporaryDirectory(prefix="xz-m58-release-flow-") as name:
            root = Path(name)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "espefuse",
                    "--chip",
                    "esp32s3",
                    "--virt",
                    "--path-efuse-file",
                    str(root / "virtual-efuse.bin"),
                    "summary",
                    "--format",
                    "json",
                    "--file",
                    str(root / "summary.json"),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise SacrificialPlanError(
                    f"virtual preflight generation failed: {result.stdout[-1000:]}"
                )
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["MAC"]["value"] = "02:00:00:00:00:01 (OK)"
            summary["MAC"]["raw_value"] = "0x020000000001"
            summary_raw = json.dumps(summary, sort_keys=True).encode("utf-8")
            request = build_request(
                plan_id="m58-current-release-test",
                transaction_id="m58-current-release-test",
                attempt_id="m58-attempt-test",
                device_id="xz-020000000001",
                serial_number="M58-SYNTHETIC-TEST",
                base_mac="02:00:00:00:00:01",
                chip_revision=1,
                release=release,
                station_id="m58-virtual-test-station",
                operators=["test-operator-a", "test-operator-b"],
                fixture_id="m58-virtual-fixture",
                fixture_version="test-1",
                fixture_calibration_sha256="40" * 32,
                authorization_key_id="m58-untrusted-test-authority",
                port_fingerprint_sha256="41" * 32,
                chip_probe=(
                    b"esptool v5.3.1\nChip is ESP32-S3 (synthetic test)\n"
                    b"MAC: 02:00:00:00:00:01\n"
                ),
                flash_probe=b"esptool v5.3.1\nDetected flash size: 16MB\n",
                tool_versions=b"esptool=5.3.1\nespefuse=5.3.1\n",
                efuse_summary_before=summary_raw,
                efuse_summary_after=summary_raw,
                efuse_check_error=b"espefuse v5.3.1\nNo errors detected.\n",
                capture_started_at="2026-08-10T10:00:00Z",
                capture_finished_at="2026-08-10T10:05:00Z",
                issued_at="2026-08-10T10:06:00Z",
                expires_at="2026-08-10T10:16:00Z",
            )
            private = Ed25519PrivateKey.generate()
            receipt = copy.deepcopy(request)
            receipt["signature_b64url"] = base64.urlsafe_b64encode(
                private.sign(canonical_json(request))
            ).rstrip(b"=").decode("ascii")
            public = private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            verify_receipt(receipt, public)
            bind_release(receipt, signing_raw, artifact_raw)
            require_active(receipt, "2026-08-10T10:10:00Z")

            ledger_root = root / "attempt-ledger"
            ledger_info = attempt_ledger.initialize_root(ledger_root)
            time_private = Ed25519PrivateKey.generate()
            time_public = time_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            policy_request = attempt_ledger.build_policy_request(
                policy_id="m59-current-release-test-policy",
                ledger_id="m59-current-release-test-ledger",
                station_id="m58-virtual-test-station",
                fixture_id="m58-virtual-fixture",
                fixture_version="test-1",
                authorization_key_id="m58-untrusted-test-authority",
                trusted_time_endpoint=(
                    "https://time.example.invalid/v1/factory/trusted-time"
                ),
                trusted_time_authority_key_id="m60-untrusted-test-time",
                trusted_time_authority_public_key_sha256=(
                    trusted_time.public_key_sha256(time_public)
                ),
                trusted_time_ca_certificate_sha256="42" * 32,
                trusted_time_client_certificate_sha256="43" * 32,
                filesystem_device=ledger_info.st_dev,
                directory_inode=ledger_info.st_ino,
                created_at="2026-08-10T09:00:00Z",
                expires_at="2026-08-10T11:00:00Z",
            )
            policy_receipt = dict(policy_request)
            policy_receipt["signature_b64url"] = base64.urlsafe_b64encode(
                private.sign(
                    attempt_ledger.POLICY_SIGNATURE_DOMAIN
                    + attempt_ledger.canonical_json(policy_request)
                )
            ).rstrip(b"=").decode("ascii")
            policy_data = attempt_ledger.canonical_json(policy_receipt)
            attempt_ledger.publish_policy(ledger_root, policy_data, public)
            plan_data = canonical_json(receipt)
            time_request = trusted_time.build_request(
                policy=policy_receipt,
                policy_data=policy_data,
                plan=receipt,
                plan_data=plan_data,
                request_id="m60-current-release-time-test",
                nonce=b"\x44" * 32,
            )
            time_receipt = trusted_time.build_receipt(
                request=time_request,
                authority_key_id="m60-untrusted-test-time",
                observed_at="2026-08-10T10:10:00Z",
                expires_at="2026-08-10T10:10:05Z",
            )
            time_receipt["signature_b64url"] = base64.urlsafe_b64encode(
                time_private.sign(
                    trusted_time.SIGNATURE_DOMAIN
                    + trusted_time.canonical_json(time_receipt)
                )
            ).rstrip(b"=").decode("ascii")
            time_receipt_data = trusted_time.canonical_json(time_receipt)
            attempt_record, _ = attempt_ledger._consume_attempt_with_receipt_for_test(
                root=ledger_root,
                plan_data=plan_data,
                authorization_public_key=public,
                signing_request_data=signing_raw,
                signed_artifact_data=artifact_raw,
                trusted_time_receipt_data=time_receipt_data,
                trusted_time_public_key=time_public,
                https_round_trip_ms=1,
            )
            checked_record, _ = attempt_ledger.verify_consumption(
                root=ledger_root,
                plan_data=plan_data,
                authorization_public_key=public,
                signing_request_data=signing_raw,
                signed_artifact_data=artifact_raw,
                trusted_time_public_key=time_public,
            )
            if checked_record != attempt_record:
                raise SacrificialPlanError("M59 consumption verification differs")
            try:
                attempt_ledger._consume_attempt_with_receipt_for_test(
                    root=ledger_root,
                    plan_data=plan_data,
                    authorization_public_key=public,
                    signing_request_data=signing_raw,
                    signed_artifact_data=artifact_raw,
                    trusted_time_receipt_data=time_receipt_data,
                    trusted_time_public_key=time_public,
                    https_round_trip_ms=1,
                )
            except attempt_ledger.AttemptAlreadyConsumed:
                pass
            else:
                raise SacrificialPlanError("M59 exact replay was not rejected")

            mixed = copy.deepcopy(receipt)
            mixed["release"]["partition_table_sha256"] = "99" * 32
            unsigned = dict(mixed)
            unsigned.pop("signature_b64url")
            mixed["signature_b64url"] = base64.urlsafe_b64encode(
                private.sign(canonical_json(unsigned))
            ).rstrip(b"=").decode("ascii")
            verify_receipt(mixed, public)
            try:
                bind_release(mixed, signing_raw, artifact_raw)
            except SacrificialPlanError:
                pass
            else:
                raise SacrificialPlanError("cross-release M58 plan was not rejected")
    except (
        OSError,
        ValueError,
        SacrificialPlanError,
        attempt_ledger.AttemptLedgerError,
        subprocess.SubprocessError,
    ) as error:
        print(f"M58 test-only release flow FAILED: {error}", file=sys.stderr)
        return 1
    print("M58 sacrificial plan flow PASS: current release binding and mix rejection")
    print("M59 attempt ledger PASS: atomic one-time consumption and replay rejection")
    print("M60 trusted-time binding PASS: signed subject time, no caller UTC")
    print("TEST ONLY: virtual/synthetic preflight and untrusted ephemeral signer; no board claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
