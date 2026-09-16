#!/usr/bin/env python3
"""Generate per-device Security-2 material and a confidential label bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import zlib
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from factory_sku_manifest import (  # noqa: E402
    FactorySKUManifestError,
    parse_and_verify_manifest,
)


AP_KEY_DOMAIN = b"xiaozhi-onboarding-ap-key-v1\n"
POP_DOMAIN = b"xiaozhi-onboarding-pop-v1\n"
MATERIAL_DOMAIN = b"xiaozhi-onboarding-material-v1\n"
MAGIC = b"PS21"
BASE32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SALT_SIZE = 16
SALT_PADDED_SIZE = 32
VERIFIER_SIZE = 384
AUTHENTICATED_SIZE = 428
AUTH_TAG_SIZE = 32
BLOB_SIZE = AUTHENTICATED_SIZE + AUTH_TAG_SIZE
USERNAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# RFC 5054 / RFC 3526 3072-bit group, matching Espressif Security 2.
N_3072 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC7"
    "4020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1"
    "4374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F4"
    "06B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8"
    "A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F3"
    "56208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905"
    "E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE"
    "2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DA"
    "D33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7"
    "DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2"
    "EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A"
    "615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120"
    "A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
G_3072 = 5


class BundleError(ValueError):
    pass


def _minimal_bytes(value: int) -> bytes:
    if value < 0:
        raise BundleError("negative integer")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _base32_prefix(value: bytes, characters: int) -> str:
    if not value or characters <= 0 or characters * 5 > len(value) * 8:
        raise BundleError("invalid base32 request")
    bits = int.from_bytes(value, "big")
    remaining = len(value) * 8
    output: list[str] = []
    for _ in range(characters):
        remaining -= 5
        output.append(BASE32[(bits >> remaining) & 31])
    return "".join(output)


def service_name(mac: str) -> str:
    if not MAC.fullmatch(mac):
        raise BundleError("MAC must use six colon-separated hex octets")
    compact = mac.replace(":", "").upper()
    return "XA-" + compact[-6:]


def generate_srp_verifier(username: str, password: str, salt: bytes) -> bytes:
    if not USERNAME.fullmatch(username):
        raise BundleError("invalid Security-2 username")
    if not password or not salt:
        raise BundleError("password and salt are required")
    inner_digest = hashlib.sha512(f"{username}:{password}".encode("utf-8")).digest()
    inner = _minimal_bytes(int.from_bytes(inner_digest, "big"))
    x = int.from_bytes(hashlib.sha512(salt + inner).digest(), "big")
    verifier = pow(G_3072, x, N_3072)
    return verifier.to_bytes(VERIFIER_SIZE, "big")


def build_bundle(
    device_hmac_key: bytes,
    mac: str,
    username: str,
    *,
    salt: bytes | None = None,
) -> tuple[bytes, dict[str, object]]:
    if len(device_hmac_key) != 32:
        raise BundleError("device HMAC key must be exactly 32 raw bytes")
    if not USERNAME.fullmatch(username):
        raise BundleError("invalid Security-2 username")
    name = service_name(mac)
    derived_key = hmac.new(
        device_hmac_key, AP_KEY_DOMAIN + name.encode("ascii"), hashlib.sha256
    ).digest()
    softap_password = _base32_prefix(derived_key, 20)
    pop_digest = hmac.new(
        device_hmac_key, POP_DOMAIN + name.encode("ascii"), hashlib.sha256
    ).digest()
    security2_password = _base32_prefix(pop_digest, 26)
    if salt is None:
        while True:
            salt = secrets.token_bytes(SALT_SIZE)
            if salt[0] != 0:
                break
    if len(salt) != SALT_SIZE or salt[0] == 0:
        raise BundleError("salt must be 16 bytes with a nonzero first octet")
    verifier = generate_srp_verifier(username, security2_password, salt)

    prefix = bytearray(AUTHENTICATED_SIZE)
    prefix[0:4] = MAGIC
    prefix[4] = 1
    prefix[5] = len(salt)
    prefix[6:8] = VERIFIER_SIZE.to_bytes(2, "little")
    prefix[8 : 8 + len(salt)] = salt
    verifier_offset = 8 + SALT_PADDED_SIZE
    prefix[verifier_offset : verifier_offset + VERIFIER_SIZE] = verifier
    prefix[-4:] = (zlib.crc32(prefix[:-4]) & 0xFFFFFFFF).to_bytes(4, "little")
    auth_tag = hmac.new(
        derived_key, MATERIAL_DOMAIN + bytes(prefix), hashlib.sha256
    ).digest()
    blob = bytes(prefix) + auth_tag
    if len(blob) != BLOB_SIZE:
        raise AssertionError("internal material size mismatch")

    qr = {
        "ver": "v1",
        "name": name,
        "username": username,
        "pop": security2_password,
        "transport": "softap",
        "security": 2,
        "password": softap_password,
    }
    qr_payload = json.dumps(qr, separators=(",", ":"), sort_keys=True)
    label = {
        "version": 1,
        "service_name": name,
        "transport": "softap",
        "security": 2,
        "security2_username": username,
        "security2_password": security2_password,
        "softap_password": softap_password,
        "qr_payload": qr_payload,
        "material_sha256": hashlib.sha256(blob).hexdigest(),
    }
    return blob, label


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise BundleError(f"output already exists: {path}") from error
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_nvs_csv(material_blob: bytes, sku_manifest: bytes) -> bytes:
    material_value = base64.b64encode(material_blob).decode("ascii")
    manifest_value = base64.b64encode(sku_manifest).decode("ascii")
    return (
        "key,type,encoding,value\n"
        "prod_prov,namespace,,\n"
        f"sec2,data,base64,{material_value}\n"
        "prod_sku,namespace,,\n"
        f"manifest,data,base64,{manifest_value}\n"
    ).encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate factory Security-2 material and confidential QR data"
    )
    parser.add_argument("--device-hmac-key", required=True, type=Path)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--username", default="xiaozhi")
    parser.add_argument("--sku-manifest", required=True, type=Path)
    parser.add_argument("--material-output", required=True, type=Path)
    parser.add_argument("--nvs-csv-output", required=True, type=Path)
    parser.add_argument("--label-output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        key_stat = arguments.device_hmac_key.stat()
        if stat.S_IMODE(key_stat.st_mode) & 0o077:
            raise BundleError("device HMAC key file must have mode 0600 or stricter")
        key = arguments.device_hmac_key.read_bytes()
        blob, label = build_bundle(key, arguments.mac, arguments.username)
        sku_manifest = arguments.sku_manifest.read_bytes()
        sku_evidence = parse_and_verify_manifest(key, sku_manifest)
        _atomic_write(arguments.material_output, blob, 0o600)
        _atomic_write(
            arguments.nvs_csv_output,
            build_nvs_csv(blob, sku_manifest),
            0o600,
        )
        label["factory_sku_manifest_sha256"] = sku_evidence[
            "manifest_sha256"
        ]
        label_text = (json.dumps(label, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        _atomic_write(arguments.label_output, label_text, 0o600)
    except (OSError, BundleError, FactorySKUManifestError) as error:
        parser.error(str(error))
    finally:
        if "key" in locals():
            key = b""
    print(
        f"onboarding bundle generated for {label['service_name']}; "
        "label output is confidential"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
