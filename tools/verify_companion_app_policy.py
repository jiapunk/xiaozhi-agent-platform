#!/usr/bin/env python3
"""Fail-closed dependency and privacy policy for the companion onboarding core."""

import argparse
import hashlib
import json
import pathlib
import plistlib
import subprocess
import sys
from typing import Dict, List


IOS_REVISION = "00a33ce4ccf79168a6cfd9d1d6cdc924d0101613"
IOS_FIX = "2d639d8925cc471742c521ddf5ff97e2d490ce9d"
PROTOBUF_REVISION = "55d7a1cc5666b85c13464aea1c4b4a90feccb4c8"
ANDROID_REVISION = "b83b78543fcd7ae24c9acbefdc17cad3ed4a3607"
ANDROID_FIX = "ad36729178fc4b054303a60fdf30e2db1133ba3d"


def _load_json(path: pathlib.Path, errors: List[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append("cannot read {}: {}".format(path, exc))
        return {}


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(checkout: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(checkout)] + list(arguments),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def _verify_checkout(
    checkout: pathlib.Path,
    revision: str,
    license_name: str,
    license_digest: str,
    fix: str,
    errors: List[str],
) -> None:
    head = _git(checkout, "rev-parse", "HEAD")
    if head.returncode or head.stdout.strip() != revision:
        errors.append("{} is not pinned at {}".format(checkout.name, revision))
    license_path = checkout / license_name
    if not license_path.is_file() or _sha256(license_path) != license_digest:
        errors.append("{} license digest changed".format(checkout.name))
    if fix:
        ancestry = _git(checkout, "merge-base", "--is-ancestor", fix, "HEAD")
        if ancestry.returncode:
            errors.append("{} does not contain reviewed Security-2 IV fix".format(checkout.name))


def verify(project: pathlib.Path, require_checkouts: bool = True) -> List[str]:
    errors: List[str] = []
    app = project / "companion-app"
    lock = _load_json(app / "upstream-lock.json", errors)
    resolved = _load_json(app / "Package.resolved", errors)
    dependencies = lock.get("dependencies", {})

    expected_lock: Dict[str, Dict[str, object]] = {
        "esp_idf_provisioning_ios": {
            "version": "3.1.0",
            "revision": IOS_REVISION,
            "license": "Apache-2.0",
            "license_sha256": "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1",
            "security2_aes_gcm_iv_fix": IOS_FIX,
        },
        "swift_protobuf": {
            "version": "1.38.1",
            "revision": PROTOBUF_REVISION,
            "license": "Apache-2.0",
            "license_sha256": "186c5f0192a754714a7e542233ddaaad28745626e0ad32e358d3f5af00afb84a",
        },
        "esp_idf_provisioning_android": {
            "version": "lib-2.4.4",
            "revision": ANDROID_REVISION,
            "license": "Apache-2.0",
            "license_sha256": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            "security2_aes_gcm_iv_fix": ANDROID_FIX,
            "library_min_sdk": 23,
            "planned_product_min_sdk": 26,
        },
    }
    if lock.get("schema_version") != 1:
        errors.append("unsupported upstream-lock schema")
    if set(dependencies) != set(expected_lock):
        errors.append("unexpected dependency set in upstream-lock")
    for name, expected in expected_lock.items():
        actual = dependencies.get(name, {})
        for key, value in expected.items():
            if actual.get(key) != value:
                errors.append("{}.{} is not reviewed value".format(name, key))

    pins = {pin.get("identity"): pin for pin in resolved.get("pins", [])}
    if set(pins) != {"esp-idf-provisioning-ios", "swift-protobuf"}:
        errors.append("Package.resolved contains an unexpected dependency set")
    expected_pins = {
        "esp-idf-provisioning-ios": ("3.1.0", IOS_REVISION),
        "swift-protobuf": ("1.38.1", PROTOBUF_REVISION),
    }
    for identity, (version, revision) in expected_pins.items():
        state = pins.get(identity, {}).get("state", {})
        if state.get("version") != version or state.get("revision") != revision:
            errors.append("{} resolution drifted".format(identity))

    package_text = (app / "Package.swift").read_text(encoding="utf-8")
    for required in (
        'exact: "3.1.0"',
        'url: "https://github.com/espressif/esp-idf-provisioning-ios.git"',
        ".iOS(.v15)",
        'name: "ProductActionConsentUI"',
        'resources: [.process("PrivacyInfo.xcprivacy")]',
    ):
        if required not in package_text:
            errors.append("Package.swift missing {}".format(required))
    if "branch:" in package_text or "from:" in package_text:
        errors.append("floating Swift package constraint is forbidden")

    privacy_path = app / "Sources/ProductOnboardingCore/PrivacyInfo.xcprivacy"
    try:
        privacy = plistlib.loads(privacy_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        errors.append("product privacy manifest is unreadable: {}".format(exc))
        privacy = {}
    expected_privacy = {
        "NSPrivacyAccessedAPITypes": [],
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
    }
    if privacy != expected_privacy:
        errors.append("product privacy manifest differs from reviewed package boundary")

    source_root = app / "Sources"
    source_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(source_root.rglob("*.swift"))
    )
    forbidden_logging = (
        "enableLogs(true)", "print(", "NSLog(", "os_log(", "Logger(",
    )
    for token in forbidden_logging:
        if token in source_text:
            errors.append("companion production source contains forbidden logging: {}".format(token))

    adapter = (
        app / "Sources/ProductOnboardingESPProvision/ESPProvisionTransport.swift"
    ).read_text(encoding="utf-8")
    for required in (
        "enableLogs(false)",
        "transport: .softap",
        "security: .secure2",
        "progress(.networkJoined)",
        "connectionTimeout: Duration = .seconds(30)",
        "provisioningTimeout: Duration = .seconds(120)",
        'sendData(path: "xz-claim", data: Data())',
        "ESP_PROVISION_CONTRACT_CHECK",
    ):
        if required not in adapter:
            errors.append("iOS adapter missing {}".format(required))
    if "progress(.deviceOnline)" in adapter:
        errors.append("transport success must not impersonate product-online proof")

    qr = (app / "Sources/ProductOnboardingCore/OnboardingQRCode.swift").read_text(
        encoding="utf-8"
    )
    for required in ("maximumBytes = 512", 'productUsername = "xiaozhi"',
                     'transport == "softap"', "security == 2"):
        if required not in qr:
            errors.append("QR contract missing {}".format(required))
    flow = (app / "Sources/ProductOnboardingCore/OnboardingFlow.swift").read_text(
        encoding="utf-8"
    )
    for required in (
        "case (.waitingForNetwork(let name), .networkJoined):",
        "case (.verifyingOwnership(let name),",
        ".ownershipStatus(let status))",
        "scheduleOwnershipStatusPoll",
    ):
        if required not in flow:
            errors.append(
                "success is not gated by authenticated ownership: {}".format(
                    required
                )
            )

    consent = (
        app / "Sources/ProductOnboardingCore/AgentActionConsent.swift"
    ).read_text(encoding="utf-8")
    for required in (
        'contract = "xz-action-consent-v1"',
        "maximumLifetime: TimeInterval = 30",
        "ownerRevision <= UInt64(UInt32.max)",
        'capability == "device.set_indicator"',
        'Set(arguments.keys) == ["on"]',
        "guard !consumed",
        '"decision":"\\#(decision.rawValue)"',
    ):
        if required not in consent:
            errors.append("action consent contract missing {}".format(required))
    consent_api = (
        app / "Sources/ProductOnboardingCore/AgentActionConsentAPI.swift"
    ).read_text(encoding="utf-8")
    for required in (
        'authority.scheme == "https"',
        'request.httpMethod = "POST"',
        'forHTTPHeaderField: "Content-Length"',
        'forHTTPHeaderField: "Cache-Control"',
        'forHTTPHeaderField: "X-Xiaozhi-Action-Consent"',
        'response.statusCode == 200',
        'request.setValue(nil, forHTTPHeaderField: "Authorization")',
    ):
        if required not in consent_api:
            errors.append("action consent API missing {}".format(required))

    consent_session = (
        app / "Sources/ProductOnboardingCore/AgentActionConsentSession.swift"
    ).read_text(encoding="utf-8")
    for required in (
        "maximumLifetime: TimeInterval = 5 * 60",
        "acquireActionConsentAccess",
        "discardActionConsentAccess",
        "func enterForeground(",
        "func leaveForeground()",
        "func signOut()",
        "generation == flow && !Task.isCancelled",
        "decisionDeliveryUnknown",
        "currentTicket === ticket",
    ):
        if required not in consent_session:
            errors.append("action consent session missing {}".format(required))
    consent_ui = (
        app / "Sources/ProductActionConsentUI/AgentActionConsentGateView.swift"
    ).read_text(encoding="utf-8")
    for required in (
        "Text(verbatim: presentation.deviceID)",
        'Text("Exact action")',
        '"Turn the indicator ON"',
        '"Turn the indicator OFF"',
        'Button("Deny", role: .cancel',
        'Button("Approve"',
        ".interactiveDismissDisabled(true)",
        '"The decision result is unknown. Do not submit it again."',
    ):
        if required not in consent_ui:
            errors.append("action consent UI missing {}".format(required))

    checkout_root = app / ".build/checkouts"
    ios_checkout = checkout_root / "esp-idf-provisioning-ios"
    protobuf_checkout = checkout_root / "swift-protobuf"
    if require_checkouts and (not ios_checkout.is_dir() or not protobuf_checkout.is_dir()):
        errors.append("resolved Swift checkouts are missing")
    if ios_checkout.is_dir():
        _verify_checkout(
            ios_checkout,
            IOS_REVISION,
            "LICENSE",
            expected_lock["esp_idf_provisioning_ios"]["license_sha256"],
            IOS_FIX,
            errors,
        )
    if protobuf_checkout.is_dir():
        _verify_checkout(
            protobuf_checkout,
            PROTOBUF_REVISION,
            "LICENSE.txt",
            expected_lock["swift_protobuf"]["license_sha256"],
            "",
            errors,
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
    )
    arguments = parser.parse_args()
    errors = verify(arguments.project.resolve())
    if errors:
        for error in errors:
            print("companion policy: {}".format(error), file=sys.stderr)
        return 1
    print("Companion App dependency/privacy policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
