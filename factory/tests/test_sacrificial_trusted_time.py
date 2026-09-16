import base64
import copy
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import sacrificial_attempt_ledger as LEDGER  # noqa: E402
import sacrificial_trusted_time as TIME  # noqa: E402
from factory.tests import test_sacrificial_attempt_ledger as M59  # noqa: E402
from factory.tests import test_sacrificial_provisioning_plan as M58  # noqa: E402


OBSERVED_AT = "2026-08-10T10:10:00Z"
EXPIRES_AT = "2026-08-10T10:10:05Z"


def pem_private(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def write_tls_material(root):
    not_before = datetime.datetime(2026, 1, 1)
    not_after = datetime.datetime(2027, 1, 1)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "M60 Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def issue(common_name, usages, san=None):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        )
        if san is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
        return key, builder.sign(ca_key, hashes.SHA256())

    server_key, server_cert = issue(
        "m60-time-server",
        [ExtendedKeyUsageOID.SERVER_AUTH],
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    )
    client_key, client_cert = issue(
        "m60-station-client", [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    paths = {
        "ca": root / "ca.pem",
        "server_cert": root / "server.pem",
        "server_key": root / "server-key.pem",
        "client_cert": root / "client.pem",
        "client_key": root / "client-key.pem",
    }
    paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths["server_cert"].write_bytes(
        server_cert.public_bytes(serialization.Encoding.PEM)
    )
    paths["server_key"].write_bytes(pem_private(server_key))
    paths["client_cert"].write_bytes(
        client_cert.public_bytes(serialization.Encoding.PEM)
    )
    paths["client_key"].write_bytes(pem_private(client_key))
    paths["server_key"].chmod(0o600)
    paths["client_key"].chmod(0o600)
    return paths


class TimeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        server = self.server
        server.requests += 1
        if self.path != TIME.ENDPOINT_PATH:
            self.send_error(404)
            return
        if not self.connection.getpeercert():
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self.send_error(400)
            return
        data = self.rfile.read(length)
        try:
            request = TIME.parse_request(data)
            receipt = TIME.build_receipt(
                request=request,
                authority_key_id=server.authority_key_id,
                observed_at=OBSERVED_AT,
                expires_at=EXPIRES_AT,
            )
            if server.mode == "cross-subject":
                receipt["transaction"]["attempt_id"] = "wrong-attempt"
            unsigned = TIME.canonical_json(receipt)
            receipt["signature_b64url"] = base64.urlsafe_b64encode(
                server.signing_key.sign(TIME.SIGNATURE_DOMAIN + unsigned)
            ).rstrip(b"=").decode("ascii")
            payload = TIME.canonical_json(receipt)
        except (ValueError, TIME.TrustedTimeError):
            self.send_error(400)
            return
        if server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", TIME.ENDPOINT_PATH)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain" if server.mode == "wrong-content-type" else "application/json",
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


class TimeServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


def start_server(paths, signing_key, authority_key_id="m60-time-test"):
    server = TimeServer(("127.0.0.1", 0), TimeHandler)
    server.signing_key = signing_key
    server.authority_key_id = authority_key_id
    server.mode = "ok"
    server.requests = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(paths["server_cert"], paths["server_key"])
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=paths["ca"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def setup_online_ledger(parent, endpoint, paths, time_public, time_key_id="m60-time-test"):
    root = parent / "ledger"
    plan, authorization_public, authorization_private = M58.signed()
    policy, policy_data = M59.signed_policy(
        root,
        authorization_private,
        authorization_public,
        trusted_time_endpoint=endpoint,
        trusted_time_authority_key_id=time_key_id,
        trusted_time_authority_public_key_sha256=TIME.public_key_sha256(time_public),
        trusted_time_ca_certificate_sha256=LEDGER.sha256(paths["ca"].read_bytes()),
        trusted_time_client_certificate_sha256=LEDGER.sha256(
            paths["client_cert"].read_bytes()
        ),
    )
    signing, artifact = M58.release_files()
    return {
        "root": root,
        "plan": plan,
        "plan_data": M58.PLAN.canonical_json(plan),
        "authorization_public": authorization_public,
        "authorization_private": authorization_private,
        "policy": policy,
        "policy_data": policy_data,
        "signing": signing,
        "artifact": artifact,
    }


class SacrificialTrustedTimeTests(unittest.TestCase):
    def test_go_m61_authority_receipt_is_accepted_by_m60_verifier(self):
        go_binary = shutil.which("go")
        if go_binary is None:
            bundled = (
                PROJECT.parent.parent
                / "work"
                / "toolchains"
                / "go1.26.5"
                / "bin"
                / "go"
            )
            if bundled.is_file():
                go_binary = str(bundled)
        if go_binary is None:
            self.skipTest("Go toolchain is not available")
        completed = subprocess.run(
            [go_binary, "run", "./tools/tests/factorytimefixture"],
            cwd=PROJECT / "gateway",
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        vector = json.loads(completed.stdout)
        request_data = base64.urlsafe_b64decode(vector["request_b64url"] + "==")
        receipt_data = base64.urlsafe_b64decode(vector["receipt_b64url"] + "==")
        public_key_data = base64.urlsafe_b64decode(
            vector["public_key_pem_b64url"] + "=="
        )
        request = TIME.parse_request(request_data)
        receipt = TIME.parse_receipt(receipt_data)
        TIME.verify_receipt(
            receipt=receipt,
            request=request,
            public_key_data=public_key_data,
            expected_authority_key_id="m61-go-test-key",
        )

    def test_signed_receipt_is_nonce_and_subject_bound(self):
        with tempfile.TemporaryDirectory(prefix="xz-m60-contract-") as name:
            parent = pathlib.Path(name)
            paths = write_tls_material(parent)
            time_private = Ed25519PrivateKey.generate()
            time_public = time_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fixture = setup_online_ledger(
                parent,
                "https://127.0.0.1:443/v1/factory/trusted-time",
                paths,
                time_public,
            )
            request = TIME.build_request(
                policy=fixture["policy"],
                policy_data=fixture["policy_data"],
                plan=fixture["plan"],
                plan_data=fixture["plan_data"],
                request_id="time-request-contract",
                nonce=b"\x31" * 32,
            )
            receipt = TIME.build_receipt(
                request=request,
                authority_key_id="m60-time-test",
                observed_at=OBSERVED_AT,
                expires_at=EXPIRES_AT,
            )
            receipt["signature_b64url"] = base64.urlsafe_b64encode(
                time_private.sign(
                    TIME.SIGNATURE_DOMAIN + TIME.canonical_json(receipt)
                )
            ).rstrip(b"=").decode("ascii")
            TIME.verify_receipt(
                receipt=receipt,
                request=request,
                public_key_data=time_public,
                expected_authority_key_id="m60-time-test",
            )
            changed = copy.deepcopy(receipt)
            changed["transaction"]["attempt_id"] = "another-attempt"
            unsigned = dict(changed)
            unsigned.pop("signature_b64url")
            changed["signature_b64url"] = base64.urlsafe_b64encode(
                time_private.sign(TIME.SIGNATURE_DOMAIN + TIME.canonical_json(unsigned))
            ).rstrip(b"=").decode("ascii")
            with self.assertRaisesRegex(TIME.TrustedTimeError, "request binding"):
                TIME.verify_receipt(
                    receipt=changed,
                    request=request,
                    public_key_data=time_public,
                    expected_authority_key_id="m60-time-test",
                )

    def test_online_mtls_consume_and_independent_verify_cli(self):
        with tempfile.TemporaryDirectory(prefix="xz-m60-online-") as name:
            parent = pathlib.Path(name)
            paths = write_tls_material(parent)
            time_private = Ed25519PrivateKey.generate()
            time_public = time_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            server, thread = start_server(paths, time_private)
            self.addCleanup(thread.join, 5)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            endpoint = (
                f"https://127.0.0.1:{server.server_address[1]}"
                f"{TIME.ENDPOINT_PATH}"
            )
            fixture = setup_online_ledger(parent, endpoint, paths, time_public)
            files = {
                "plan": fixture["plan_data"],
                "authorization-public": fixture["authorization_public"],
                "signing": fixture["signing"],
                "artifact": fixture["artifact"],
                "time-public": time_public,
            }
            file_paths = {}
            for label, data in files.items():
                path = parent / label
                path.write_bytes(data)
                file_paths[label] = path
            environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            base = [
                "--root",
                str(fixture["root"]),
                "--plan",
                str(file_paths["plan"]),
                "--authorization-public-key",
                str(file_paths["authorization-public"]),
                "--signing-request",
                str(file_paths["signing"]),
                "--signed-artifact-verification",
                str(file_paths["artifact"]),
                "--trusted-time-public-key",
                str(file_paths["time-public"]),
            ]
            consumed = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "consume_sacrificial_attempt.py"),
                    *base,
                    "--trusted-time-ca-certificate",
                    str(paths["ca"]),
                    "--trusted-time-client-certificate",
                    str(paths["client_cert"]),
                    "--trusted-time-client-private-key",
                    str(paths["client_key"]),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                timeout=20,
            )
            self.assertEqual(consumed.returncode, 0, consumed.stdout)
            self.assertIn("executor_invoked=false", consumed.stdout)
            checked = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "verify_sacrificial_attempt_consumption.py"),
                    *base,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                timeout=20,
            )
            self.assertEqual(checked.returncode, 0, checked.stdout)
            self.assertEqual(server.requests, 1)

    def test_redirect_content_type_and_cross_subject_fail_before_consumption(self):
        for mode, message in (
            ("redirect", "rejected request"),
            ("wrong-content-type", "content type"),
            ("cross-subject", "request binding"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="xz-m60-negative-"
            ) as name:
                parent = pathlib.Path(name)
                paths = write_tls_material(parent)
                time_private = Ed25519PrivateKey.generate()
                time_public = time_private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                server, thread = start_server(paths, time_private)
                server.mode = mode
                try:
                    endpoint = (
                        f"https://127.0.0.1:{server.server_address[1]}"
                        f"{TIME.ENDPOINT_PATH}"
                    )
                    fixture = setup_online_ledger(parent, endpoint, paths, time_public)
                    with self.assertRaisesRegex(LEDGER.AttemptLedgerError, message):
                        LEDGER.consume_attempt_online(
                            root=fixture["root"],
                            plan_data=fixture["plan_data"],
                            authorization_public_key=fixture["authorization_public"],
                            signing_request_data=fixture["signing"],
                            signed_artifact_data=fixture["artifact"],
                            trusted_time_public_key=time_public,
                            ca_certificate=paths["ca"],
                            ca_certificate_data=paths["ca"].read_bytes(),
                            client_certificate=paths["client_cert"],
                            client_certificate_data=paths["client_cert"].read_bytes(),
                            client_private_key=paths["client_key"],
                        )
                    self.assertFalse(any((fixture["root"] / "claims").glob("*.json")))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(5)

    def test_tls_and_signing_pins_fail_without_network_request(self):
        with tempfile.TemporaryDirectory(prefix="xz-m60-pins-") as name:
            parent = pathlib.Path(name)
            paths = write_tls_material(parent)
            time_private = Ed25519PrivateKey.generate()
            time_public = time_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            server, thread = start_server(paths, time_private)
            try:
                endpoint = (
                    f"https://127.0.0.1:{server.server_address[1]}"
                    f"{TIME.ENDPOINT_PATH}"
                )
                fixture = setup_online_ledger(parent, endpoint, paths, time_public)
                wrong_time_public = Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "material differs"):
                    LEDGER.consume_attempt_online(
                        root=fixture["root"],
                        plan_data=fixture["plan_data"],
                        authorization_public_key=fixture["authorization_public"],
                        signing_request_data=fixture["signing"],
                        signed_artifact_data=fixture["artifact"],
                        trusted_time_public_key=wrong_time_public,
                        ca_certificate=paths["ca"],
                        ca_certificate_data=paths["ca"].read_bytes(),
                        client_certificate=paths["client_cert"],
                        client_certificate_data=paths["client_cert"].read_bytes(),
                        client_private_key=paths["client_key"],
                    )
                self.assertEqual(server.requests, 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(5)


if __name__ == "__main__":
    unittest.main()
