#!/usr/bin/env python3
"""Strictly validate and verify a signed factory enrollment receipt."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from factory_flash_manifest import (  # noqa: E402
    FactoryFlashManifestError,
    parse_manifest_bytes,
    read_regular,
)
from factory_physical_observation import (  # noqa: E402
    PhysicalObservationError,
    parse_canonical as parse_physical_observation,
    verify_receipt as verify_physical_observation,
)


MAX_RECEIPT_BYTES = 64 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,64}$")
RECEIPT_ID = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
MAC_ADDRESS = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
DEVICE_ID = re.compile(r"^xz-[0-9a-f]{12}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_ID = re.compile(r"^[0-9a-f]{32}$")


class ReceiptError(ValueError):
    pass


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_receipt_bytes(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt must be 1..65536 bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReceiptError("receipt is not UTF-8") from error
    try:
        receipt = json.loads(text, object_pairs_hook=_object_pairs)
    except (json.JSONDecodeError, ReceiptError) as error:
        raise ReceiptError(f"invalid receipt JSON: {error}") from error
    if not isinstance(receipt, dict):
        raise ReceiptError("receipt root must be an object")
    return receipt


def _exact_object(value: Any, required: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{path} must be an object")
    missing = required - value.keys()
    extra = value.keys() - required
    if missing or extra:
        raise ReceiptError(
            f"{path} members differ: missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return value


def _string(value: Any, pattern: re.Pattern[str], path: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ReceiptError(f"{path} has invalid format")
    return value


def _integer(value: Any, minimum: int, maximum: int, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptError(f"{path} must be an integer")
    if value < minimum or value > maximum:
        raise ReceiptError(f"{path} is outside {minimum}..{maximum}")
    return value


def _must_be_true(value: Any, path: str) -> None:
    if value is not True:
        raise ReceiptError(f"{path} must be true for a PASS receipt")


def _must_be_false(value: Any, path: str) -> None:
    if value is not False:
        raise ReceiptError(f"{path} must be false for a PASS receipt")


def _base64url(value: Any, decoded_size: int, path: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ReceiptError(f"{path} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise ReceiptError(f"{path} is invalid base64url") from error
    if len(decoded) != decoded_size or (
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise ReceiptError(f"{path} is non-canonical or has the wrong size")
    return decoded


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReceiptError(f"{path} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ReceiptError(f"{path} is not a valid timestamp") from error
    if parsed.microsecond != 0:
        raise ReceiptError(f"{path} must use whole seconds")
    return parsed


def _protected_hmac_key(value: Any, path: str) -> dict[str, Any]:
    key = _exact_object(
        value,
        {
            "slot",
            "purpose",
            "read_protected",
            "write_protected",
            "purpose_write_protected",
            "confirmation_b64url",
        },
        path,
    )
    _integer(key["slot"], 0, 5, f"{path}.slot")
    if key["purpose"] != "HMAC_UP":
        raise ReceiptError(f"{path}.purpose must be HMAC_UP")
    _must_be_true(key["read_protected"], f"{path}.read_protected")
    _must_be_true(key["write_protected"], f"{path}.write_protected")
    _must_be_true(
        key["purpose_write_protected"],
        f"{path}.purpose_write_protected",
    )
    _base64url(
        key["confirmation_b64url"], 32, f"{path}.confirmation_b64url"
    )
    return key


def validate_receipt(receipt: dict[str, Any]) -> None:
    root = _exact_object(
        receipt,
        {
            "version",
            "receipt_id",
            "device_id",
            "serial_number",
            "chip",
            "product_identity",
            "station",
            "identity_key",
            "secure_storage",
            "boot_security",
            "onboarding",
            "registry",
            "firmware",
            "tests",
            "started_at",
            "finished_at",
            "result",
            "signature_algorithm",
            "receipt_signature_b64url",
        },
        "receipt",
    )
    _integer(root["version"], 4, 4, "version")
    _string(root["receipt_id"], RECEIPT_ID, "receipt_id")
    _string(root["device_id"], DEVICE_ID, "device_id")
    _string(root["serial_number"], IDENTIFIER, "serial_number")
    if root["result"] != "PASS":
        raise ReceiptError("result must be PASS")
    if root["signature_algorithm"] != "Ed25519":
        raise ReceiptError("signature_algorithm must be Ed25519")

    chip = _exact_object(
        root["chip"],
        {"model", "base_mac", "softap_mac", "revision"},
        "chip",
    )
    if chip["model"] != "ESP32-S3":
        raise ReceiptError("chip.model must be ESP32-S3")
    _string(chip["base_mac"], MAC_ADDRESS, "chip.base_mac")
    _string(chip["softap_mac"], MAC_ADDRESS, "chip.softap_mac")
    _integer(chip["revision"], 0, 999, "chip.revision")
    expected_device_id = "xz-" + chip["base_mac"].replace(":", "").lower()
    if root["device_id"] != expected_device_id:
        raise ReceiptError(
            "device_id must equal xz- followed by the lowercase base MAC"
        )

    product_identity = _exact_object(
        root["product_identity"],
        {
            "sku",
            "board",
            "hardware_revision",
            "chip_revision",
            "base_mac",
            "manifest_schema",
            "manifest_id",
            "factory_record_version",
            "manifest_sha256",
            "manifest_size",
            "nvs_namespace",
            "nvs_key",
            "authentication_domain",
            "identity_hmac_key_slot",
            "runtime_verification_pass",
        },
        "product_identity",
    )
    if product_identity["sku"] != "VOICE_AGENT_KIT_BOX3":
        raise ReceiptError("product_identity.sku must be VOICE_AGENT_KIT_BOX3")
    if product_identity["board"] != "esp32s3-box3":
        raise ReceiptError("product_identity.board must be esp32s3-box3")
    _integer(
        product_identity["hardware_revision"], 1, 1,
        "product_identity.hardware_revision",
    )
    product_chip_revision = _integer(
        product_identity["chip_revision"], 0, 999,
        "product_identity.chip_revision",
    )
    if product_chip_revision != chip["revision"]:
        raise ReceiptError(
            "product identity chip revision differs from observed chip"
        )
    product_base_mac = _string(
        product_identity["base_mac"], MAC_ADDRESS,
        "product_identity.base_mac",
    )
    if product_base_mac != chip["base_mac"]:
        raise ReceiptError(
            "product identity base MAC differs from observed chip"
        )
    _integer(
        product_identity["manifest_schema"], 1, 1,
        "product_identity.manifest_schema",
    )
    manifest_id = _string(
        product_identity["manifest_id"], MANIFEST_ID,
        "product_identity.manifest_id",
    )
    if manifest_id in ("0" * 32, "f" * 32):
        raise ReceiptError("product_identity.manifest_id is reserved")
    product_record_version = _integer(
        product_identity["factory_record_version"], 1, 2**32 - 1,
        "product_identity.factory_record_version",
    )
    manifest_sha256 = _string(
        product_identity["manifest_sha256"], SHA256_HEX,
        "product_identity.manifest_sha256",
    )
    _integer(
        product_identity["manifest_size"], 70, 70,
        "product_identity.manifest_size",
    )
    if product_identity["nvs_namespace"] != "prod_sku":
        raise ReceiptError("product_identity.nvs_namespace must be prod_sku")
    if product_identity["nvs_key"] != "manifest":
        raise ReceiptError("product_identity.nvs_key must be manifest")
    if product_identity["authentication_domain"] != (
        "XIAOZHI-PRODUCT-SKU-MANIFEST-V1"
    ):
        raise ReceiptError(
            "product identity authentication domain is invalid"
        )
    _integer(
        product_identity["identity_hmac_key_slot"], 5, 5,
        "product_identity.identity_hmac_key_slot",
    )
    _must_be_true(
        product_identity["runtime_verification_pass"],
        "product_identity.runtime_verification_pass",
    )

    station = _exact_object(
        root["station"],
        {
            "id",
            "operators",
            "espefuse_version",
            "fixture_version",
            "signing_key_id",
        },
        "station",
    )
    _string(station["id"], IDENTIFIER, "station.id")
    _string(station["espefuse_version"], IDENTIFIER, "station.espefuse_version")
    _string(station["fixture_version"], IDENTIFIER, "station.fixture_version")
    _string(station["signing_key_id"], IDENTIFIER, "station.signing_key_id")
    operators = station["operators"]
    if not isinstance(operators, list) or not 2 <= len(operators) <= 4:
        raise ReceiptError("station.operators must contain 2..4 operator IDs")
    checked_operators = [
        _string(item, IDENTIFIER, "station.operators[]") for item in operators
    ]
    if len(set(checked_operators)) != len(checked_operators):
        raise ReceiptError("station.operators must be distinct")

    identity_key = _protected_hmac_key(root["identity_key"], "identity_key")
    if identity_key["slot"] != 5:
        raise ReceiptError("identity_key.slot must be frozen key block 5")

    secure_storage = _exact_object(
        root["secure_storage"],
        {
            "key",
            "credential_partition",
            "encryption_scheme",
            "factory_partition",
            "factory_material_public_only",
        },
        "secure_storage",
    )
    storage_key = _protected_hmac_key(
        secure_storage["key"], "secure_storage.key"
    )
    if storage_key["slot"] != 4:
        raise ReceiptError("secure_storage.key.slot must be frozen key block 4")
    if secure_storage["credential_partition"] != "nvs":
        raise ReceiptError("secure_storage.credential_partition must be nvs")
    if secure_storage["encryption_scheme"] != "HMAC_XTS_AES":
        raise ReceiptError(
            "secure_storage.encryption_scheme must be HMAC_XTS_AES"
        )
    if secure_storage["factory_partition"] != "nvs_factory":
        raise ReceiptError("secure_storage.factory_partition must be nvs_factory")
    _must_be_true(
        secure_storage["factory_material_public_only"],
        "secure_storage.factory_material_public_only",
    )

    boot_security = _exact_object(
        root["boot_security"],
        {
            "secure_boot_scheme",
            "secure_boot_digests",
            "flash_encryption_key",
            "secure_download_mode",
            "jtag_disabled",
            "read_protect_lock_closed",
            "anti_rollback_efuse_version",
            "signing_request_sha256",
            "signed_artifact_verification_sha256",
            "encrypted_flash_manifest_sha256",
            "efuse_summary_sha256",
        },
        "boot_security",
    )
    if boot_security["secure_boot_scheme"] != "RSA-3072":
        raise ReceiptError("boot_security.secure_boot_scheme must be RSA-3072")
    digests = boot_security["secure_boot_digests"]
    if not isinstance(digests, list) or len(digests) != 3:
        raise ReceiptError("boot_security.secure_boot_digests must have three entries")
    digest_values: list[str] = []
    digest_key_ids: list[str] = []
    for expected_slot, value in enumerate(digests):
        path = f"boot_security.secure_boot_digests[{expected_slot}]"
        digest = _exact_object(
            value,
            {
                "slot",
                "purpose",
                "key_id",
                "digest_sha256",
                "read_protected",
                "write_protected",
                "purpose_write_protected",
            },
            path,
        )
        if _integer(digest["slot"], 0, 2, f"{path}.slot") != expected_slot:
            raise ReceiptError(f"{path}.slot is not sequential")
        expected_purpose = f"SECURE_BOOT_DIGEST{expected_slot}"
        if digest["purpose"] != expected_purpose:
            raise ReceiptError(f"{path}.purpose must be {expected_purpose}")
        digest_key_ids.append(_string(digest["key_id"], IDENTIFIER, f"{path}.key_id"))
        digest_values.append(
            _string(digest["digest_sha256"], SHA256_HEX, f"{path}.digest_sha256")
        )
        _must_be_false(digest["read_protected"], f"{path}.read_protected")
        _must_be_true(digest["write_protected"], f"{path}.write_protected")
        _must_be_true(
            digest["purpose_write_protected"],
            f"{path}.purpose_write_protected",
        )
    if len(set(digest_key_ids)) != 3 or len(set(digest_values)) != 3:
        raise ReceiptError("Secure Boot key IDs and digests must be distinct")

    flash_key = _exact_object(
        boot_security["flash_encryption_key"],
        {
            "slot",
            "purpose",
            "read_protected",
            "write_protected",
            "purpose_write_protected",
        },
        "boot_security.flash_encryption_key",
    )
    if flash_key["slot"] != 3 or flash_key["purpose"] != "XTS_AES_128_KEY":
        raise ReceiptError("Flash Encryption must use block 3 XTS_AES_128_KEY")
    for name in ("read_protected", "write_protected", "purpose_write_protected"):
        _must_be_true(flash_key[name], f"boot_security.flash_encryption_key.{name}")
    for name in ("secure_download_mode", "jtag_disabled", "read_protect_lock_closed"):
        _must_be_true(boot_security[name], f"boot_security.{name}")
    anti_rollback_version = _integer(
        boot_security["anti_rollback_efuse_version"],
        1,
        16,
        "boot_security.anti_rollback_efuse_version",
    )
    _string(
        boot_security["signing_request_sha256"],
        SHA256_HEX,
        "boot_security.signing_request_sha256",
    )
    _string(
        boot_security["signed_artifact_verification_sha256"],
        SHA256_HEX,
        "boot_security.signed_artifact_verification_sha256",
    )
    _string(
        boot_security["encrypted_flash_manifest_sha256"],
        SHA256_HEX,
        "boot_security.encrypted_flash_manifest_sha256",
    )
    _string(
        boot_security["efuse_summary_sha256"],
        SHA256_HEX,
        "boot_security.efuse_summary_sha256",
    )

    onboarding = _exact_object(
        root["onboarding"],
        {
            "material_sha256",
            "nvs_factory_readback_sha256",
            "label_issue_id",
            "security2_transaction_pass",
        },
        "onboarding",
    )
    _string(
        onboarding["material_sha256"],
        SHA256_HEX,
        "onboarding.material_sha256",
    )
    _string(
        onboarding["nvs_factory_readback_sha256"],
        SHA256_HEX,
        "onboarding.nvs_factory_readback_sha256",
    )
    _string(onboarding["label_issue_id"], RECEIPT_ID, "onboarding.label_issue_id")
    _must_be_true(
        onboarding["security2_transaction_pass"],
        "onboarding.security2_transaction_pass",
    )

    registry = _exact_object(
        root["registry"],
        {
            "record_version",
            "committed",
            "sku",
            "board",
            "hardware_revision",
            "factory_manifest_sha256",
        },
        "registry",
    )
    registry_version = _integer(
        registry["record_version"], 1, 2**31 - 1,
        "registry.record_version",
    )
    _must_be_true(registry["committed"], "registry.committed")
    if registry_version != product_record_version:
        raise ReceiptError(
            "registry record version differs from factory manifest"
        )
    if registry["sku"] != product_identity["sku"]:
        raise ReceiptError("registry SKU differs from factory manifest")
    if registry["board"] != product_identity["board"]:
        raise ReceiptError("registry board differs from factory manifest")
    if registry["hardware_revision"] != product_identity["hardware_revision"]:
        raise ReceiptError(
            "registry hardware revision differs from factory manifest"
        )
    if registry["factory_manifest_sha256"] != manifest_sha256:
        raise ReceiptError("registry factory manifest digest differs")

    firmware = _exact_object(
        root["firmware"],
        {
            "sha256",
            "secure_boot_v2",
            "flash_encryption_release_mode",
            "security_version",
        },
        "firmware",
    )
    _string(firmware["sha256"], SHA256_HEX, "firmware.sha256")
    _must_be_true(firmware["secure_boot_v2"], "firmware.secure_boot_v2")
    _must_be_true(
        firmware["flash_encryption_release_mode"],
        "firmware.flash_encryption_release_mode",
    )
    firmware_secure_version = _integer(
        firmware["security_version"],
        1,
        16,
        "firmware.security_version",
    )
    if firmware_secure_version != anti_rollback_version:
        raise ReceiptError(
            "firmware.security_version must equal anti-rollback eFuse version"
        )

    tests = _exact_object(
        root["tests"],
        {
            "efuse_summary_pass",
            "identity_hmac_challenge_pass",
            "storage_hmac_challenge_pass",
            "encrypted_nvs_roundtrip_pass",
            "onboarding_button_gesture_pass",
            "factory_sku_identity_pass",
            "session_issuance_pass",
            "wss_upgrade_pass",
            "signed_bootloader_verification_pass",
            "signed_app_verification_pass",
            "flash_encryption_roundtrip_pass",
            "anti_rollback_rejection_pass",
            "secure_download_mode_pass",
        },
        "tests",
    )
    for name, value in tests.items():
        _must_be_true(value, f"tests.{name}")

    started = _timestamp(root["started_at"], "started_at")
    finished = _timestamp(root["finished_at"], "finished_at")
    if finished < started:
        raise ReceiptError("finished_at precedes started_at")
    _base64url(root["receipt_signature_b64url"], 64, "receipt_signature_b64url")


def canonical_payload(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("receipt_signature_b64url", None)
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_receipt(receipt: dict[str, Any], public_key_pem: bytes) -> None:
    validate_receipt(receipt)
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise ReceiptError("invalid station public key PEM") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReceiptError("station public key must be Ed25519")
    signature = _base64url(
        receipt["receipt_signature_b64url"], 64, "receipt_signature_b64url"
    )
    try:
        public_key.verify(signature, canonical_payload(receipt))
    except InvalidSignature as error:
        raise ReceiptError("receipt signature verification failed") from error


def validate_encrypted_flash_manifest_binding(
    receipt: dict[str, Any],
    manifest: dict[str, Any],
    manifest_raw: bytes,
    physical_observation: dict[str, Any],
    physical_observation_raw: bytes,
) -> None:
    transaction = manifest["transaction"]
    release = manifest["release"]
    material = manifest["factory_material"]
    product = receipt["product_identity"]
    boot = receipt["boot_security"]
    if hashlib.sha256(manifest_raw).hexdigest() != boot[
        "encrypted_flash_manifest_sha256"
    ]:
        raise ReceiptError("encrypted-flash manifest digest differs from receipt")
    expected_transaction = {
        "device_id": receipt["device_id"],
        "serial_number": receipt["serial_number"],
        "base_mac": receipt["chip"]["base_mac"],
        "sku": product["sku"],
        "board": product["board"],
        "hardware_revision": product["hardware_revision"],
        "chip_revision": product["chip_revision"],
        "factory_record_version": product["factory_record_version"],
        "factory_manifest_id": product["manifest_id"],
        "factory_manifest_sha256": product["manifest_sha256"],
    }
    for name, expected in expected_transaction.items():
        if transaction[name] != expected:
            raise ReceiptError(
                f"encrypted-flash manifest transaction {name} differs from receipt"
            )
    expected_release = {
        "signing_request_sha256": boot["signing_request_sha256"],
        "signed_artifact_verification_sha256": boot[
            "signed_artifact_verification_sha256"
        ],
        "anti_rollback_secure_version": receipt["firmware"]["security_version"],
        "application_unsigned_sha256": receipt["firmware"]["sha256"],
    }
    for name, expected in expected_release.items():
        if release[name] != expected:
            raise ReceiptError(
                f"encrypted-flash manifest release {name} differs from receipt"
            )
    receipt_digests = [
        {"slot": item["slot"], "digest_sha256": item["digest_sha256"]}
        for item in boot["secure_boot_digests"]
    ]
    if release["secure_boot_digests"] != receipt_digests:
        raise ReceiptError("encrypted-flash manifest Secure Boot digests differ")
    expected_material = {
        "onboarding_material_sha256": receipt["onboarding"]["material_sha256"],
        "factory_sku_manifest_sha256": product["manifest_sha256"],
        "nvs_factory_readback_sha256": receipt["onboarding"][
            "nvs_factory_readback_sha256"
        ],
    }
    for name, expected in expected_material.items():
        if material[name] != expected:
            raise ReceiptError(
                f"encrypted-flash manifest factory material {name} differs from receipt"
            )
    provenance = manifest["physical_flash_observation"]
    expected_provenance = {
        "schema": physical_observation["schema"],
        "observation_id": physical_observation["observation_id"],
        "environment": physical_observation["environment"],
        "phase": physical_observation["phase"],
        "station_id": physical_observation["station"]["id"],
        "signing_key_id": physical_observation["station"]["signing_key_id"],
        "receipt_sha256": hashlib.sha256(physical_observation_raw).hexdigest(),
    }
    if provenance != expected_provenance:
        raise ReceiptError("physical flash observation provenance differs from manifest")
    expected_observation_transaction = {
        "transaction_id": transaction["transaction_id"],
        "attempt_id": transaction["attempt_id"],
        "device_id": transaction["device_id"],
        "serial_number": transaction["serial_number"],
        "base_mac": transaction["base_mac"],
    }
    if physical_observation["transaction"] != expected_observation_transaction:
        raise ReceiptError("physical flash observation transaction differs")
    if (
        physical_observation["product"]["sku"] != transaction["sku"]
        or physical_observation["product"]["board"] != transaction["board"]
        or physical_observation["product"]["hardware_revision"]
        != transaction["hardware_revision"]
        or physical_observation["product"]["chip_revision"]
        != transaction["chip_revision"]
    ):
        raise ReceiptError("physical flash observation product differs")
    if physical_observation["release"] != {
        "signing_request_sha256": release["signing_request_sha256"],
        "signed_artifact_verification_sha256": release[
            "signed_artifact_verification_sha256"
        ],
        "anti_rollback_secure_version": release["anti_rollback_secure_version"],
    }:
        raise ReceiptError("physical flash observation release differs")
    expected_regions = [
        {
            "name": item["name"],
            "offset": item["offset"],
            "size": item["size"],
            "readback_sha256": item["readback_sha256"],
        }
        for item in manifest["programmed_regions"]
    ]
    if physical_observation["capture"]["regions"] != expected_regions:
        raise ReceiptError("physical flash observation readbacks differ from manifest")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and verify an ESP Agent factory receipt"
    )
    parser.add_argument("receipt", type=Path)
    parser.add_argument("station_public_key", type=Path)
    parser.add_argument(
        "--encrypted-flash-manifest",
        required=True,
        type=Path,
        help="complete M55 per-unit manifest whose digest is signed by the receipt",
    )
    parser.add_argument(
        "--physical-observation",
        required=True,
        type=Path,
        help="externally signed M56 physical flash readback observation",
    )
    parser.add_argument(
        "--physical-observation-public-key",
        required=True,
        type=Path,
        help="trusted physical-readback station Ed25519 public key",
    )
    arguments = parser.parse_args()
    try:
        receipt = parse_receipt_bytes(arguments.receipt.read_bytes())
        verify_receipt(receipt, arguments.station_public_key.read_bytes())
        manifest_raw = read_regular(
            arguments.encrypted_flash_manifest,
            256 * 1024,
            "encrypted-flash manifest",
        )
        manifest = parse_manifest_bytes(manifest_raw)
        physical_observation_raw = read_regular(
            arguments.physical_observation,
            128 * 1024,
            "physical flash observation",
        )
        physical_observation = parse_physical_observation(
            physical_observation_raw, signed=True
        )
        verify_physical_observation(
            physical_observation,
            read_regular(
                arguments.physical_observation_public_key,
                16 * 1024,
                "physical observation public key",
            ),
        )
        validate_encrypted_flash_manifest_binding(
            receipt,
            manifest,
            manifest_raw,
            physical_observation,
            physical_observation_raw,
        )
    except (
        OSError,
        ReceiptError,
        FactoryFlashManifestError,
        PhysicalObservationError,
    ) as error:
        print(f"factory receipt rejected: {error}", file=sys.stderr)
        return 1
    print(
        f"factory receipt verified: {receipt['receipt_id']} "
        f"device={receipt['device_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
