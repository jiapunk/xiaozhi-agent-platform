#!/usr/bin/env python3
"""Create an immutable, P-256 signed product OTA release manifest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import verify_reset_hardware_qualification as reset_qualification


APP_DESC_OFFSET = 32
APP_DESC_MAGIC = 0xABCD5432
MAX_IMAGE_SIZE = 2**31 - 1
MAX_VALIDITY_SECONDS = 30 * 24 * 60 * 60
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,64}$")
SHORT_IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,32}$")
VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,32}$")
AUTHORITY = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]{11,107}$")
MANIFEST_FIELDS = {
    "schema",
    "release_id",
    "project",
    "board",
    "channel",
    "version",
    "release_sequence",
    "secure_version",
    "image_url",
    "image_size",
    "image_sha256",
    "reset_qualification_sha256",
    "not_before",
    "expires_at",
    "signing_key_id",
    "signature_algorithm",
    "signature_b64url",
}


class ManifestError(ValueError):
    pass


def _decode_c_string(value: bytes, field: str) -> str:
    raw = value.split(b"\0", 1)[0]
    if not raw:
        raise ManifestError(f"image {field} is empty")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ManifestError(f"image {field} is not ASCII") from error


def read_app_description(image: bytes) -> tuple[str, str, int]:
    required = APP_DESC_OFFSET + 80
    if len(image) < required:
        raise ManifestError("image is too small for an ESP app descriptor")
    magic, secure_version = struct.unpack_from("<II", image, APP_DESC_OFFSET)
    if magic != APP_DESC_MAGIC:
        raise ManifestError("ESP app descriptor magic is missing")
    version = _decode_c_string(
        image[APP_DESC_OFFSET + 16 : APP_DESC_OFFSET + 48], "version"
    )
    project = _decode_c_string(
        image[APP_DESC_OFFSET + 48 : APP_DESC_OFFSET + 80], "project"
    )
    if not VERSION.fullmatch(version) or not SHORT_IDENTIFIER.fullmatch(project):
        raise ManifestError("image project/version has unsupported format")
    return project, version, secure_version


def read_build_policy(sdkconfig_text: str) -> tuple[str, str, int]:
    values: dict[str, str] = {}
    for line in sdkconfig_text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    if values.get("CONFIG_PRODUCT_BOARD_ESP_BOX_3") == "y":
        board = "esp32s3-box3"
    elif values.get("CONFIG_PRODUCT_BOARD_S3_N32R16_REFERENCE") == "y":
        board = "esp32s3-n32r16"
    else:
        raise ManifestError("sdkconfig has no supported product board")
    channel_value = values.get("CONFIG_PRODUCT_OTA_CHANNEL")
    if not channel_value or len(channel_value) < 2 or not (
        channel_value.startswith('"') and channel_value.endswith('"')
    ):
        raise ManifestError("sdkconfig has no quoted OTA channel")
    channel = channel_value[1:-1]
    if not SHORT_IDENTIFIER.fullmatch(channel):
        raise ManifestError("sdkconfig OTA channel has invalid format")
    try:
        sequence = int(values["CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE"], 10)
    except (KeyError, ValueError) as error:
        raise ManifestError("sdkconfig has no OTA release sequence") from error
    if not 1 <= sequence <= 2**31 - 1:
        raise ManifestError("OTA release sequence is outside range")
    return board, channel, sequence


def validate_authority(authority: str) -> None:
    if not AUTHORITY.fullmatch(authority) or authority.count(":") > 1:
        raise ManifestError("image URL authority has invalid syntax")
    host, separator, port_text = authority.partition(":")
    labels = host.split(".")
    if any(
        not 1 <= len(label) <= 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not character.isalnum() and character != "-" for character in label)
        for label in labels
    ):
        raise ManifestError("image URL authority must contain valid DNS labels")
    if separator:
        if not port_text.isascii() or not port_text.isdigit():
            raise ManifestError("image URL port must be numeric")
        port = int(port_text, 10)
        if not 1 <= port <= 65535:
            raise ManifestError("image URL port is outside range")


def validate_image_url(url: str) -> None:
    if len(url) > 512 or not url.startswith("https://") or "\\" in url:
        raise ManifestError("image URL must be a bounded HTTPS URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path
        or parsed.path == "/"
        or parsed.query
        or parsed.fragment
        or any(ord(character) <= 0x20 or ord(character) >= 0x7F for character in url)
    ):
        raise ManifestError(
            "image URL must use one DNS authority and a non-secret path"
        )
    validate_authority(parsed.netloc)


def _exact_integer(value: object, minimum: int, maximum: int, field: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ManifestError(f"manifest {field} is outside range")
    return value


def validate_manifest_shape(manifest: dict[str, object]) -> None:
    if set(manifest) != MANIFEST_FIELDS:
        raise ManifestError("manifest fields do not match schema v2")
    if manifest.get("schema") != 2:
        raise ManifestError("manifest schema is unsupported")
    for field, expression in (
        ("release_id", IDENTIFIER),
        ("project", SHORT_IDENTIFIER),
        ("board", SHORT_IDENTIFIER),
        ("channel", SHORT_IDENTIFIER),
        ("version", VERSION),
        ("signing_key_id", IDENTIFIER),
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or not expression.fullmatch(value):
            raise ManifestError(f"manifest {field} has invalid format")
    _exact_integer(manifest.get("release_sequence"), 1, 2**31 - 1,
                   "release_sequence")
    _exact_integer(manifest.get("secure_version"), 0, 2**32 - 1,
                   "secure_version")
    _exact_integer(manifest.get("image_size"), 1024, MAX_IMAGE_SIZE,
                   "image_size")
    not_before = _exact_integer(manifest.get("not_before"), 1609459200,
                                4102444800, "not_before")
    expires_at = _exact_integer(manifest.get("expires_at"), 1609459200,
                                4102444800, "expires_at")
    if expires_at <= not_before or expires_at - not_before > MAX_VALIDITY_SECONDS:
        raise ManifestError("manifest validity window is invalid or too long")
    image_url = manifest.get("image_url")
    if not isinstance(image_url, str):
        raise ManifestError("manifest image_url has invalid format")
    validate_image_url(image_url)
    for field in ("image_sha256", "reset_qualification_sha256"):
        digest = manifest.get(field)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ManifestError(f"manifest {field} has invalid format")
    if manifest.get("signature_algorithm") != "ECDSA_P256_SHA256":
        raise ManifestError("manifest signature algorithm is unsupported")
    encoded = manifest.get("signature_b64url")
    if not isinstance(encoded, str) or not BASE64URL.fullmatch(encoded):
        raise ManifestError("signature is not bounded unpadded base64url")
    try:
        signature = base64.urlsafe_b64decode(
            encoded + "=" * ((4 - len(encoded) % 4) % 4)
        )
    except ValueError as error:
        raise ManifestError("signature is not unpadded base64url") from error
    if not 8 <= len(signature) <= 80 or (
        base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii") != encoded
    ):
        raise ManifestError("signature encoding is non-canonical or outside range")


def load_manifest_json(data: bytes) -> dict[str, object]:
    if not 1 <= len(data) <= 8192 or b"\\u0000" in data.lower():
        raise ManifestError("manifest JSON size or content is invalid")

    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ManifestError("manifest contains duplicate fields")
            result[key] = value
        return result

    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError("manifest is not strict UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise ManifestError("manifest root must be an object")
    validate_manifest_shape(parsed)
    return parsed


def canonical_payload(manifest: dict[str, object]) -> bytes:
    return (
        "xiaozhi-product-ota-v2\n"
        f"board={manifest['board']}\n"
        f"channel={manifest['channel']}\n"
        f"expires_at={manifest['expires_at']}\n"
        f"image_sha256={manifest['image_sha256']}\n"
        f"image_size={manifest['image_size']}\n"
        f"image_url={manifest['image_url']}\n"
        f"not_before={manifest['not_before']}\n"
        f"project={manifest['project']}\n"
        f"release_id={manifest['release_id']}\n"
        f"release_sequence={manifest['release_sequence']}\n"
        f"reset_qualification_sha256={manifest['reset_qualification_sha256']}\n"
        f"schema={manifest['schema']}\n"
        f"secure_version={manifest['secure_version']}\n"
        f"signature_algorithm={manifest['signature_algorithm']}\n"
        f"signing_key_id={manifest['signing_key_id']}\n"
        f"version={manifest['version']}\n"
    ).encode("ascii")


def build_manifest(
    image: bytes,
    sdkconfig_text: str,
    private_key_pem: bytes,
    reset_qualification_receipt: bytes,
    reset_qualification_public_key_pem: bytes,
    reset_qualification_signing_key_id: str,
    *,
    release_id: str,
    image_url: str,
    not_before: int,
    expires_at: int,
    signing_key_id: str,
) -> dict[str, object]:
    if not 1024 <= len(image) <= MAX_IMAGE_SIZE:
        raise ManifestError("image size is outside manifest range")
    if not IDENTIFIER.fullmatch(release_id):
        raise ManifestError("release ID has invalid format")
    if not IDENTIFIER.fullmatch(signing_key_id):
        raise ManifestError("signing key ID has invalid format")
    if (
        not 1609459200 <= not_before <= 4102444800
        or not 1609459200 <= expires_at <= 4102444800
        or expires_at <= not_before
        or expires_at - not_before > MAX_VALIDITY_SECONDS
    ):
        raise ManifestError("manifest validity window is invalid or too long")
    validate_image_url(image_url)
    project, version, secure_version = read_app_description(image)
    board, channel, sequence = read_build_policy(sdkconfig_text)
    image_sha256 = hashlib.sha256(image).hexdigest()
    try:
        reset_qualification.verify_receipt_bytes(
            reset_qualification_receipt,
            reset_qualification_public_key_pem,
            expected_board=board,
            expected_project=project,
            expected_version=version,
            expected_secure_version=secure_version,
            expected_image_sha256=image_sha256,
            expected_signing_key_id=reset_qualification_signing_key_id,
        )
    except reset_qualification.QualificationError as error:
        raise ManifestError(f"reset hardware qualification failed: {error}") from error
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=None
        )
    except (TypeError, ValueError) as error:
        raise ManifestError("invalid unencrypted release private key PEM") from error
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise ManifestError("release key must be ECDSA P-256")
    manifest: dict[str, object] = {
        "schema": 2,
        "release_id": release_id,
        "project": project,
        "board": board,
        "channel": channel,
        "version": version,
        "release_sequence": sequence,
        "secure_version": secure_version,
        "image_url": image_url,
        "image_size": len(image),
        "image_sha256": image_sha256,
        "reset_qualification_sha256": hashlib.sha256(
            reset_qualification_receipt
        ).hexdigest(),
        "not_before": not_before,
        "expires_at": expires_at,
        "signing_key_id": signing_key_id,
        "signature_algorithm": "ECDSA_P256_SHA256",
    }
    signature = private_key.sign(canonical_payload(manifest), ec.ECDSA(hashes.SHA256()))
    manifest["signature_b64url"] = (
        base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    )
    return manifest


def verify_manifest_signature(
    manifest: dict[str, object], public_key_pem: bytes
) -> None:
    validate_manifest_shape(manifest)
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise ManifestError("invalid release public key PEM") from error
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ManifestError("release public key must be ECDSA P-256")
    encoded = manifest["signature_b64url"]
    assert isinstance(encoded, str)
    try:
        signature = base64.urlsafe_b64decode(
            encoded + "=" * ((4 - len(encoded) % 4) % 4)
        )
        public_key.verify(
            signature, canonical_payload(manifest), ec.ECDSA(hashes.SHA256())
        )
    except (ValueError, InvalidSignature) as error:
        raise ManifestError("release manifest signature verification failed") from error


def verify_release_artifacts(
    manifest: dict[str, object],
    public_key_pem: bytes,
    image: bytes,
    sdkconfig_text: str,
    *,
    expected_authority: str,
    reset_qualification_receipt: bytes | None = None,
    reset_qualification_public_key_pem: bytes | None = None,
    reset_qualification_signing_key_id: str | None = None,
) -> None:
    verify_manifest_signature(manifest, public_key_pem)
    validate_authority(expected_authority)
    image_url = manifest["image_url"]
    assert isinstance(image_url, str)
    if urlsplit(image_url).netloc.lower() != expected_authority.lower():
        raise ManifestError("manifest image authority is not the release authority")
    project, version, secure_version = read_app_description(image)
    board, channel, sequence = read_build_policy(sdkconfig_text)
    expected = {
        "project": project,
        "version": version,
        "secure_version": secure_version,
        "board": board,
        "channel": channel,
        "release_sequence": sequence,
        "image_size": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise ManifestError(f"manifest {field} does not match release artifacts")
    reset_inputs = (
        reset_qualification_receipt,
        reset_qualification_public_key_pem,
        reset_qualification_signing_key_id,
    )
    if any(value is None for value in reset_inputs) and any(
        value is not None for value in reset_inputs
    ):
        raise ManifestError("reset qualification receipt, public key and key ID are inseparable")
    if reset_qualification_receipt is not None:
        try:
            reset_qualification.verify_receipt_bytes(
                reset_qualification_receipt,
                reset_qualification_public_key_pem or b"",
                expected_board=board,
                expected_project=project,
                expected_version=version,
                expected_secure_version=secure_version,
                expected_image_sha256=hashlib.sha256(image).hexdigest(),
                expected_signing_key_id=reset_qualification_signing_key_id or "",
            )
        except reset_qualification.QualificationError as error:
            raise ManifestError(
                f"reset hardware qualification failed: {error}"
            ) from error
        if manifest.get("reset_qualification_sha256") != hashlib.sha256(
            reset_qualification_receipt
        ).hexdigest():
            raise ManifestError(
                "manifest reset_qualification_sha256 does not match receipt"
            )


def _publish_new(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ManifestError("output already exists")
    if not path.parent.is_dir():
        raise ManifestError("output directory does not exist")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise ManifestError("output already exists") from error
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sign an immutable XiaoZhi Agent OTA release manifest"
    )
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--sdkconfig", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--reset-qualification-receipt", required=True, type=Path)
    parser.add_argument("--reset-qualification-public-key", required=True, type=Path)
    parser.add_argument("--reset-qualification-signing-key-id", required=True)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--image-url", required=True)
    parser.add_argument("--not-before", required=True, type=int)
    parser.add_argument("--expires-at", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        key_mode = stat.S_IMODE(arguments.private_key.stat().st_mode)
        if key_mode & 0o077:
            raise ManifestError("release private key file must be mode 0600 or stricter")
        manifest = build_manifest(
            arguments.image.read_bytes(),
            arguments.sdkconfig.read_text(encoding="utf-8"),
            arguments.private_key.read_bytes(),
            arguments.reset_qualification_receipt.read_bytes(),
            arguments.reset_qualification_public_key.read_bytes(),
            arguments.reset_qualification_signing_key_id,
            release_id=arguments.release_id,
            image_url=arguments.image_url,
            not_before=arguments.not_before,
            expires_at=arguments.expires_at,
            signing_key_id=arguments.signing_key_id,
        )
        output = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        _publish_new(arguments.output, output)
    except (OSError, ManifestError) as error:
        parser.error(str(error))
    print(
        f"signed OTA manifest {manifest['release_id']} created for "
        f"{manifest['board']} sequence={manifest['release_sequence']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
