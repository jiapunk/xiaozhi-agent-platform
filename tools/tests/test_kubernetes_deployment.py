from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import struct
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import kubernetes_deployment as K8S
import oci_release as OCI


SOURCE_DATE_EPOCH = 1786276800


def fake_elf(architecture: str) -> bytes:
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, OCI.GO_MACHINES[architecture])
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    return bytes(data)


def compile_fixture(project: pathlib.Path, go: pathlib.Path, service: str,
                    architecture: str, output: pathlib.Path) -> None:
    del project, go
    output.write_bytes(fake_elf(architecture) + service.encode())


def unlock_tree(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


def tree_digest(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


class KubernetesDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go 1.26.5 is not available")
        self.go = pathlib.Path(go).resolve()
        if OCI._go_version(self.go) != "go1.26.5":
            self.skipTest("tests require pinned Go 1.26.5")
        self.oci_private = Ed25519PrivateKey.generate()
        self.deploy_private = Ed25519PrivateKey.generate()
        self.oci_private_path, self.oci_public_path = self.write_keypair(
            "oci", self.oci_private)
        self.deploy_private_path, self.deploy_public_path = self.write_keypair(
            "deployment", self.deploy_private)
        self.ca_path = self.temporary / "ca.pem"
        self.ca_path.write_bytes(
            b"-----BEGIN CERTIFICATE-----\nZmFrZS1jYS1mb3ItdGVzdHM=\n-----END CERTIFICATE-----\n"
        )
        self.oci_bundle = self.temporary / "oci"
        self.bundle = self.temporary / "deployment"
        self.profile = PROJECT / "deployment/kubernetes-deployment-profile.example.json"
        OCI.build_release_bundle(
            project_root=PROJECT,
            go_binary=self.go,
            ca_bundle_path=self.ca_path,
            signing_private_key_path=self.oci_private_path,
            signing_key_id="m49-oci-key",
            release_id="m49-oci-release",
            version="0.49.0-test",
            source_date_epoch=SOURCE_DATE_EPOCH,
            output_path=self.oci_bundle,
            compile_callback=compile_fixture,
        )

    def tearDown(self) -> None:
        for root in (self.bundle, self.temporary / "deployment-2", self.oci_bundle):
            unlock_tree(root)
        shutil.rmtree(self.temporary, ignore_errors=True)

    def write_keypair(self, prefix: str, key: Ed25519PrivateKey) -> tuple[pathlib.Path, pathlib.Path]:
        private_path = self.temporary / f"{prefix}-private.pem"
        public_path = self.temporary / f"{prefix}-public.pem"
        private_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        public_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        return private_path, public_path

    def build(self, output: pathlib.Path | None = None,
              profile: pathlib.Path | None = None) -> dict[str, object]:
        return K8S.build_bundle(
            oci_bundle=self.oci_bundle,
            oci_trusted_public_key=self.oci_public_path,
            oci_signing_key_id="m49-oci-key",
            expected_oci_release_id="m49-oci-release",
            profile_path=profile or self.profile,
            signing_private_key_path=self.deploy_private_path,
            signing_key_id="m49-deployment-key",
            output_path=output or self.bundle,
        )

    def validate(self) -> dict[str, object]:
        return K8S.validate_bundle(
            self.bundle,
            oci_bundle=self.oci_bundle,
            oci_trusted_public_key=self.oci_public_path,
            expected_oci_signing_key_id="m49-oci-key",
            expected_oci_release_id="m49-oci-release",
            trusted_public_key=self.deploy_public_path,
            expected_signing_key_id="m49-deployment-key",
            expected_deployment_id="m49-pilot",
        )

    def resign(self, receipt: dict[str, object], domain: bytes | None = None) -> None:
        unsigned = dict(receipt)
        unsigned.pop("signature_b64url", None)
        payload = (domain or K8S.SIGNATURE_DOMAIN) + OCI._compact_bytes(unsigned)
        receipt["signature_b64url"] = OCI._b64url(self.deploy_private.sign(payload))
        data = OCI._json_bytes(receipt)
        (self.bundle / "deployment-receipt.json").write_bytes(data)
        (self.bundle / "READY").write_text(hashlib.sha256(data).hexdigest() + "\n")

    def test_builds_exact_digest_only_hardened_bundle(self) -> None:
        receipt = self.build()
        self.assertEqual(self.validate(), receipt)
        resources = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(), "Kubernetes resources")
        items = resources["items"]
        self.assertEqual(len(items), 44)
        self.assertEqual(
            {item["kind"] for item in items},
            {"ServiceAccount", "Service", "Deployment", "StatefulSet", "NetworkPolicy"},
        )
        self.assertFalse(any(item["kind"] in {"Secret", "ConfigMap"} for item in items))
        workloads = [item for item in items if item["kind"] in {"Deployment", "StatefulSet"}]
        self.assertEqual(len(workloads), 7)
        for workload in workloads:
            pod = workload["spec"]["template"]["spec"]
            container = pod["containers"][0]
            self.assertRegex(container["image"], r"@sha256:[0-9a-f]{64}$")
            self.assertNotIn(":latest", container["image"])
            self.assertFalse(pod["automountServiceAccountToken"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
            self.assertEqual(pod["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})

    def test_private_service_probes_and_ingress_are_exact(self) -> None:
        self.build()
        items = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(), "Kubernetes resources")["items"]
        account = next(item for item in items if item["kind"] == "Deployment" and
                       item["metadata"]["labels"]["app.kubernetes.io/component"] == "accountauthorization")
        container = account["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["livenessProbe"]["httpGet"],
                         {"path": "/healthz", "port": 9080, "scheme": "HTTP"})
        self.assertEqual(container["readinessProbe"]["httpGet"],
                         {"path": "/readyz", "port": 9080, "scheme": "HTTP"})
        account_service = next(item for item in items if item["kind"] == "Service" and
                               item["metadata"]["labels"]["app.kubernetes.io/component"] == "accountauthorization")
        self.assertEqual(account_service["spec"]["ports"],
                         [{"name": "https", "port": 9444, "protocol": "TCP", "targetPort": "https"}])
        ingress = next(item for item in items if item["kind"] == "NetworkPolicy" and
                       item["metadata"]["name"] == "m49-pilot-account-internal")
        self.assertEqual(ingress["spec"]["ingress"][0]["from"],
                         [
                             {"podSelector": {"matchLabels": {
                                 "app.kubernetes.io/component": "controlplane"
                             }}},
                             {"namespaceSelector": {"matchLabels": {
                                 "kubernetes.io/metadata.name": "xiaozhi-release"
                             }}},
                         ])
        factory_time = next(
            item for item in items
            if item["kind"] == "Deployment"
            and item["metadata"]["labels"]["app.kubernetes.io/component"]
            == "factorytimeauthority"
        )
        factory_container = factory_time["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(
            factory_container["livenessProbe"]["httpGet"],
            {"path": "/healthz", "port": 9081, "scheme": "HTTP"},
        )
        self.assertEqual(
            factory_container["readinessProbe"]["httpGet"],
            {"path": "/readyz", "port": 9081, "scheme": "HTTP"},
        )
        factory_service = next(
            item for item in items
            if item["kind"] == "Service"
            and item["metadata"]["labels"]["app.kubernetes.io/component"]
            == "factorytimeauthority"
        )
        self.assertEqual(
            factory_service["spec"]["ports"],
            [{"name": "https", "port": 9445, "protocol": "TCP", "targetPort": "https"}],
        )
        station_ingress = next(
            item for item in items
            if item["kind"] == "NetworkPolicy"
            and item["metadata"]["name"] == "m49-pilot-factory-time-station-ingress"
        )
        self.assertEqual(
            station_ingress["spec"]["ingress"][0]["ports"],
            [{"port": 9445, "protocol": "TCP"}],
        )

    def test_companion_push_is_profile_bound_without_an_eighth_workload(self) -> None:
        self.build()
        items = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(),
            "Kubernetes resources",
        )["items"]
        workloads = [item for item in items
                     if item["kind"] in {"Deployment", "StatefulSet"}]
        self.assertEqual(len(workloads), 7)
        by_service = {
            item["metadata"]["labels"]["app.kubernetes.io/component"]: item
            for item in workloads
        }
        control_env = by_service["controlplane"]["spec"]["template"]["spec"][
            "containers"][0]["env"]
        account_env = by_service["accountauthorization"]["spec"]["template"][
            "spec"]["containers"][0]["env"]
        control_by_name = {item["name"]: item for item in control_env}
        account_by_name = {item["name"]: item for item in account_env}
        self.assertEqual(
            control_by_name["ACTION_CONSENT_PUSH_ENABLED"],
            {"name": "ACTION_CONSENT_PUSH_ENABLED", "value": "true"},
        )
        self.assertEqual(
            control_by_name["ACTION_CONSENT_PUSH_WORKER_ID"]["valueFrom"],
            {"fieldRef": {"fieldPath": "metadata.name"}},
        )
        self.assertEqual(
            account_by_name["COMPANION_PUSH_FCM_CREDENTIAL_MODE"]["value"],
            "service-account",
        )
        account_files = next(
            volume for volume in
            by_service["accountauthorization"]["spec"]["template"]["spec"]["volumes"]
            if volume["name"] == "service-files"
        )["secret"]
        self.assertEqual(
            [item["key"] for item in account_files["items"]],
            [
                "tls.crt", "tls.key", "control-client-ca.pem",
                "entitlement-update-keyring.json",
                "telemetry-ca.pem", "telemetry-client.crt",
                "telemetry-client.key",
                "push-token-keyring.json", "apns-private-key.p8",
                "fcm-service-account.json",
            ],
        )
        account_egress = next(
            item for item in items if item["kind"] == "NetworkPolicy" and
            item["metadata"]["name"] == "m49-pilot-accountauthorization-egress"
        )
        self.assertTrue(any(
            rule.get("ports") == [{"port": 443, "protocol": "TCP"}]
            for rule in account_egress["spec"]["egress"]
        ))

    def test_runtime_coordination_is_pod_bound_and_database_scoped(self) -> None:
        self.build()
        items = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(),
            "Kubernetes resources",
        )["items"]
        workloads = {
            item["metadata"]["labels"]["app.kubernetes.io/component"]: item
            for item in items if item["kind"] in {"Deployment", "StatefulSet"}
        }
        for service in ("gateway", "controlplane", "agentproxy"):
            environment = workloads[service]["spec"]["template"]["spec"][
                "containers"][0]["env"]
            worker = next(
                item for item in environment
                if item["name"] == "RUNTIME_COORDINATION_WORKER_ID"
            )
            self.assertEqual(
                worker,
                {"name": "RUNTIME_COORDINATION_WORKER_ID",
                 "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
            )
            egress = next(
                item for item in items if item["kind"] == "NetworkPolicy"
                and item["metadata"]["name"] == f"m49-pilot-{service}-egress"
            )
            self.assertTrue(any(
                rule.get("ports") == [{"port": 5432, "protocol": "TCP"}]
                for rule in egress["spec"]["egress"]
            ))
        prerequisites = OCI._strict_json(
            (self.bundle / "prerequisites.json").read_bytes(), "prerequisites")
        for service in ("gateway", "controlplane", "agentproxy"):
            secret = next(
                item for item in prerequisites["objects"]
                if item.get("service") == service
                and item.get("purpose") == "secret-environment"
            )
            self.assertIn("OWNERSHIP_DATABASE_URL", secret["required_keys"])

    def test_gateway_speech_identities_are_separate_secret_files(self) -> None:
        self.build()
        items = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(),
            "Kubernetes resources",
        )["items"]
        workloads = [item for item in items
                     if item["kind"] in {"Deployment", "StatefulSet"}]
        self.assertEqual(len(workloads), 7)
        gateway = next(
            item for item in workloads
            if item["metadata"]["labels"]["app.kubernetes.io/component"] == "gateway"
        )
        container = gateway["spec"]["template"]["spec"]["containers"][0]
        environment = {item["name"]: item.get("value") for item in container["env"]}
        self.assertEqual(environment["STT_TLS_CA_FILE"], "/run/secrets/files/stt-ca.pem")
        self.assertEqual(environment["STT_TLS_CLIENT_CERT_FILE"],
                         "/run/secrets/files/stt-client.crt")
        self.assertEqual(environment["STT_TLS_CLIENT_KEY_FILE"],
                         "/run/secrets/files/stt-client.key")
        self.assertEqual(environment["TTS_TLS_CA_FILE"], "/run/secrets/files/tts-ca.pem")
        self.assertEqual(environment["TTS_TLS_CLIENT_CERT_FILE"],
                         "/run/secrets/files/tts-client.crt")
        self.assertEqual(environment["TTS_TLS_CLIENT_KEY_FILE"],
                         "/run/secrets/files/tts-client.key")
        service_files = next(
            volume for volume in gateway["spec"]["template"]["spec"]["volumes"]
            if volume["name"] == "service-files"
        )["secret"]
        speech_keys = [item["key"] for item in service_files["items"]
                       if item["key"].startswith(("stt-", "tts-"))]
        self.assertEqual(speech_keys, [
            "stt-ca.pem", "stt-client.crt", "stt-client.key",
            "tts-ca.pem", "tts-client.crt", "tts-client.key",
        ])
        prerequisites = OCI._strict_json(
            (self.bundle / "prerequisites.json").read_bytes(), "prerequisites")
        gateway_files = next(
            item for item in prerequisites["objects"]
            if item.get("service") == "gateway"
            and item.get("purpose") == "secret-files"
        )
        self.assertEqual(
            [key for key in gateway_files["required_keys"]
             if key.startswith(("stt-", "tts-"))],
            speech_keys,
        )

    def test_content_free_telemetry_is_seven_service_bound_and_network_scoped(self) -> None:
        self.build()
        items = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(),
            "Kubernetes resources",
        )["items"]
        workloads = {
            item["metadata"]["labels"]["app.kubernetes.io/component"]: item
            for item in items if item["kind"] in {"Deployment", "StatefulSet"}
        }
        self.assertEqual(set(workloads), set(K8S.SERVICES))
        telemetry_secret_names = set()
        expected_endpoint = (
            "https://otel-collector.xiaozhi-monitoring.svc:4318/v1/traces"
        )
        for service, workload in workloads.items():
            pod = workload["spec"]["template"]["spec"]
            environment = {
                item["name"]: item.get("value")
                for item in pod["containers"][0]["env"]
            }
            self.assertEqual(
                environment["TELEMETRY_OTLP_TRACES_ENDPOINT"], expected_endpoint
            )
            self.assertEqual(environment["TELEMETRY_DEPLOYMENT_ID"], "m49-pilot")
            self.assertEqual(environment["TELEMETRY_TRACE_SAMPLE_RATIO_PPM"], "1000000")
            self.assertEqual(environment["TELEMETRY_OTLP_TIMEOUT_MS"], "2000")
            volume = next(
                value for value in pod["volumes"]
                if value["name"] == "service-files"
            )["secret"]
            telemetry_secret_names.add(volume["secretName"])
            keys = {value["key"] for value in volume["items"]}
            self.assertTrue({
                "telemetry-ca.pem", "telemetry-client.crt",
                "telemetry-client.key",
            }.issubset(keys))
            egress = next(
                item for item in items if item["kind"] == "NetworkPolicy"
                and item["metadata"]["name"] == f"m49-pilot-{service}-egress"
            )
            telemetry_rules = [
                rule for rule in egress["spec"]["egress"]
                if rule.get("ports") == [{"port": 4318, "protocol": "TCP"}]
            ]
            self.assertEqual(telemetry_rules, [{
                "ports": [{"port": 4318, "protocol": "TCP"}],
                "to": [{
                    "namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": "xiaozhi-monitoring"
                    }},
                    "podSelector": {"matchLabels": {
                        "app.kubernetes.io/name": "otel-collector"
                    }},
                }],
            }])
        self.assertEqual(len(telemetry_secret_names), 7)

    def test_managed_token_keyrings_replace_production_environment_keys(self) -> None:
        self.build()
        items = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(),
            "Kubernetes resources",
        )["items"]
        workloads = {
            item["metadata"]["labels"]["app.kubernetes.io/component"]: item
            for item in items if item["kind"] in {"Deployment", "StatefulSet"}
        }
        self.assertEqual(len(workloads), 7)
        expected = {
            "gateway": {"VOICE_TOKEN_HMAC_KEYRING_FILE": "voice-token-keyring.json"},
            "controlplane": {
                "VOICE_TOKEN_HMAC_KEYRING_FILE": "voice-token-keyring.json",
                "AGENT_TOKEN_HMAC_KEYRING_FILE": "agent-token-keyring.json",
                "OTA_TOKEN_HMAC_KEYRING_FILE": "ota-token-keyring.json",
            },
            "agentproxy": {"AGENT_TOKEN_HMAC_KEYRING_FILE": "agent-token-keyring.json"},
            "firmwareorigin": {"OTA_TOKEN_HMAC_KEYRING_FILE": "ota-token-keyring.json"},
        }
        for service, variables in expected.items():
            container = workloads[service]["spec"]["template"]["spec"]["containers"][0]
            environment = {item["name"]: item.get("value") for item in container["env"]}
            volume = next(
                item for item in workloads[service]["spec"]["template"]["spec"]["volumes"]
                if item["name"] == "service-files"
            )["secret"]
            file_keys = {item["key"] for item in volume["items"]}
            for variable, filename in variables.items():
                self.assertEqual(environment[variable], f"/run/secrets/files/{filename}")
                self.assertIn(filename, file_keys)

        prerequisites = OCI._strict_json(
            (self.bundle / "prerequisites.json").read_bytes(), "prerequisites")
        forbidden_environment = {
            "DEVICE_TOKEN_HMAC_KEYS_B64", "VOICE_TOKEN_HMAC_KEY_B64",
            "AGENT_TOKEN_HMAC_KEY_B64", "AGENT_TOKEN_HMAC_KEYS_B64",
            "OTA_TOKEN_HMAC_KEY_B64", "OTA_TOKEN_HMAC_KEYS_B64",
        }
        for service in expected:
            secret_environment = next(
                item for item in prerequisites["objects"]
                if item.get("service") == service
                and item.get("purpose") == "secret-environment"
            )
            self.assertTrue(
                forbidden_environment.isdisjoint(secret_environment["required_keys"])
            )
            config = next(
                item for item in prerequisites["objects"]
                if item.get("service") == service
                and item.get("purpose") == "service-config"
            )
            for variable in expected[service]:
                floor = variable.replace("_FILE", "_MIN_REVISION")
                self.assertIn(floor, config["required_keys"])

    def test_prerequisites_inventory_contains_no_secret_values(self) -> None:
        self.build()
        data = (self.bundle / "prerequisites.json").read_bytes()
        prerequisites = OCI._strict_json(data, "prerequisites")
        def assert_no_values(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue({"data", "stringData"}.isdisjoint(value))
                for child in value.values():
                    assert_no_values(child)
            elif isinstance(value, list):
                for child in value:
                    assert_no_values(child)
        assert_no_values(prerequisites)
        self.assertEqual(len(prerequisites["objects"]), 30)
        account_env = next(item for item in prerequisites["objects"]
                           if item.get("service") == "accountauthorization" and
                           item.get("purpose") == "secret-environment")
        self.assertEqual(account_env["required_keys"], ["ACCOUNT_AUTHORIZATION_DATABASE_URL"])
        account_files = next(item for item in prerequisites["objects"]
                             if item.get("service") == "accountauthorization" and
                             item.get("purpose") == "secret-files")
        self.assertEqual(account_files["required_keys"], [
            "tls.crt", "tls.key", "control-client-ca.pem",
            "entitlement-update-keyring.json",
            "telemetry-ca.pem", "telemetry-client.crt", "telemetry-client.key",
            "push-token-keyring.json", "apns-private-key.p8",
            "fcm-service-account.json",
        ])
        factory_files = next(
            item for item in prerequisites["objects"]
            if item.get("service") == "factorytimeauthority"
            and item.get("purpose") == "secret-files"
        )
        self.assertEqual(
            factory_files["required_keys"],
            [
                "tls.crt", "tls.key", "station-client-ca.pem", "signer.pub",
                "signer-ca.pem", "signer-client.crt", "signer-client.key",
                "telemetry-ca.pem", "telemetry-client.crt",
                "telemetry-client.key",
            ],
        )
        workload_namespace = next(item for item in prerequisites["objects"]
                                  if item.get("purpose") == "workload")
        self.assertEqual(workload_namespace["required_labels"]["xiaozhi-agent/deployment-id"],
                         "m49-pilot")
        image_pull = next(item for item in prerequisites["objects"]
                          if item.get("purpose") == "registry-auth")
        self.assertTrue(image_pull["immutable_required"])

    def test_same_inputs_are_byte_for_byte_reproducible(self) -> None:
        self.build()
        second = self.temporary / "deployment-2"
        self.build(second)
        self.assertEqual(tree_digest(self.bundle), tree_digest(second))

    def test_validly_resigned_manifest_policy_tamper_is_rejected(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        path = self.bundle / "kubernetes.json"
        resources = OCI._strict_json(path.read_bytes(), "Kubernetes resources")
        workload = next(item for item in resources["items"] if item["kind"] == "Deployment")
        workload["spec"]["template"]["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = False
        data = OCI._json_bytes(resources)
        path.write_bytes(data)
        receipt = OCI._strict_json(
            (self.bundle / "deployment-receipt.json").read_bytes(), "receipt")
        receipt["kubernetes_sha256"] = hashlib.sha256(data).hexdigest()
        self.resign(receipt)
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(K8S.DeploymentError, "hardened contract"):
            self.validate()

    def test_profile_rejects_broad_egress_mutable_registry_and_shared_secrets(self) -> None:
        base = OCI._strict_json(self.profile.read_bytes(), "profile")
        mutations = (
            ("broad egress", lambda value: value["external_egress"].__setitem__("provider", ["0.0.0.0/0"]), "default egress route"),
            ("cross-domain egress", lambda value: value["external_egress"].__setitem__("provider", value["external_egress"]["identity"]), "overlap across"),
            ("tagged registry", lambda value: value.__setitem__("registry_repository", "registry.example/xiaozhi:latest"), "registry repository"),
            ("shared secrets", lambda value: value["secret_env"].__setitem__("gateway", value["secret_env"]["controlplane"]), "isolated"),
            ("shared namespace", lambda value: value.__setitem__("monitoring_namespace", value["namespace"]), "distinct"),
            ("push without provider", lambda value: value.__setitem__("companion_push", {"enabled": True, "apns": False, "fcm_credential_mode": "disabled"}), "at least one provider"),
            ("provider while disabled", lambda value: value.__setitem__("companion_push", {"enabled": False, "apns": True, "fcm_credential_mode": "disabled"}), "cannot configure providers"),
            ("telemetry wildcard selector", lambda value: value["telemetry"].__setitem__("pod_selector", {}), "telemetry pod selector"),
            ("telemetry zero sampling", lambda value: value["telemetry"].__setitem__("sample_ratio_ppm", 0), "telemetry sample ratio"),
            ("telemetry excessive timeout", lambda value: value["telemetry"].__setitem__("timeout_ms", 5001), "telemetry timeout"),
            ("unsafe pricing profile", lambda value: value["agent_usage"].__setitem__("pricing_profile_id", "unsafe profile"), "pricing profile ID"),
            ("zero Agent budget", lambda value: value["agent_usage"].__setitem__("daily_budget_microusd", 0), "daily_budget_microusd"),
            ("boolean Agent rate", lambda value: value["agent_usage"].__setitem__("input_microusd_per_million_tokens", True), "input_microusd"),
            ("unsafe speech pricing profile", lambda value: value["speech_usage"].__setitem__("pricing_profile_id", "unsafe profile"), "speech usage pricing profile ID"),
            ("zero speech budget", lambda value: value["speech_usage"].__setitem__("daily_budget_microusd", 0), "speech usage daily_budget_microusd"),
            ("no TTS billing dimension", lambda value: (value["speech_usage"].__setitem__("tts_microusd_per_million_characters", 0), value["speech_usage"].__setitem__("tts_microusd_per_million_output_audio_ms", 0)), "at least one TTS billing dimension"),
            ("short Voice entitlement token", lambda value: value["service_entitlement"].__setitem__("voice_token_ttl_seconds", 59), "voice_token_ttl_seconds"),
            ("long Agent entitlement token", lambda value: value["service_entitlement"].__setitem__("agent_token_ttl_seconds", 901), "agent_token_ttl_seconds"),
            ("boolean entitlement token", lambda value: value["service_entitlement"].__setitem__("agent_token_ttl_seconds", True), "agent_token_ttl_seconds"),
            ("zero entitlement trust revision", lambda value: value["entitlement_update_trust"].__setitem__("keyring_min_revision", 0), "keyring_min_revision"),
            ("long entitlement authorization", lambda value: value["entitlement_update_trust"].__setitem__("authorization_ttl_seconds", 301), "authorization_ttl_seconds"),
            ("boolean entitlement trust revision", lambda value: value["entitlement_update_trust"].__setitem__("keyring_min_revision", True), "keyring_min_revision"),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                value = OCI._strict_json(OCI._json_bytes(base), "profile copy")
                mutate(value)
                with self.assertRaisesRegex(K8S.DeploymentError, message):
                    K8S.validate_profile(value)

    def test_json_schemas_fix_seven_services_and_external_prerequisites(self) -> None:
        profile_schema = OCI._strict_json(
            (PROJECT / "deployment/kubernetes-deployment-profile.schema.json").read_bytes(),
            "profile schema")
        receipt_schema = OCI._strict_json(
            (PROJECT / "deployment/kubernetes-deployment-receipt.schema.json").read_bytes(),
            "receipt schema")
        self.assertTrue(profile_schema["$id"].endswith("kubernetes-deployment-profile-v7.json"))
        self.assertEqual(profile_schema["properties"]["schema"]["const"], 7)
        self.assertEqual(receipt_schema["properties"]["schema"]["const"], 7)
        entitlement = profile_schema["properties"]["service_entitlement"]
        self.assertEqual(
            set(entitlement["required"]),
            {"voice_token_ttl_seconds", "agent_token_ttl_seconds"},
        )
        service_names = profile_schema["$defs"]["serviceNames"]
        self.assertEqual(set(service_names["required"]), set(K8S.SERVICES))
        self.assertFalse(service_names["additionalProperties"])
        services = receipt_schema["properties"]["services"]
        self.assertEqual((services["minItems"], services["maxItems"]), (7, 7))
        self.assertEqual(set(services["items"]["properties"]["name"]["enum"]),
                         set(K8S.SERVICES))
        prerequisites = K8S.build_prerequisites(K8S.load_profile(self.profile)[0])
        self.assertFalse(any("value" in item for item in prerequisites["objects"]))

    def test_service_entitlement_bounds_voice_and_agent_token_ttls(self) -> None:
        profile, _ = K8S.load_profile(self.profile)
        gateway = {item["name"]: item.get("value") for item in
                   K8S._fixed_env(profile, "gateway")}
        control = {item["name"]: item.get("value") for item in
                   K8S._fixed_env(profile, "controlplane")}
        agent = {item["name"]: item.get("value") for item in
                 K8S._fixed_env(profile, "agentproxy")}
        self.assertEqual(gateway["DEVICE_TOKEN_MAX_TTL_SECONDS"], "300")
        self.assertEqual(control["VOICE_TOKEN_TTL_SECONDS"], "300")
        self.assertEqual(control["AGENT_TOKEN_TTL_SECONDS"], "240")
        self.assertEqual(agent["AGENT_TOKEN_MAX_TTL_SECONDS"], "240")
        self.assertEqual(
            control["SERVICE_ENTITLEMENT_AUTHORIZATION_URL"],
            "https://m49-pilot-accountauthorization:9444/"
            "v1/service-entitlements/authorize",
        )

    def test_entitlement_update_trust_is_signed_and_regular_file_mounted(self) -> None:
        profile, _ = K8S.load_profile(self.profile)
        self.assertEqual(profile["entitlement_update_trust"], {
            "authorization_ttl_seconds": 300,
            "keyring_min_revision": 1,
        })
        account_environment = {
            item["name"]: item.get("value")
            for item in K8S._fixed_env(profile, "accountauthorization")
        }
        self.assertEqual(
            account_environment["ENTITLEMENT_UPDATE_KEYRING_FILE"],
            "/run/secrets/files/entitlement-update-keyring.json",
        )
        self.assertEqual(
            account_environment["ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION"],
            "1",
        )
        self.assertEqual(
            account_environment["ENTITLEMENT_UPDATE_AUTHORIZATION_TTL_SECONDS"],
            "300",
        )
        self.build()
        resources = OCI._strict_json(
            (self.bundle / "kubernetes.json").read_bytes(),
            "Kubernetes resources",
        )["items"]
        account = next(
            item for item in resources
            if item["kind"] == "Deployment"
            and item["metadata"]["labels"]["app.kubernetes.io/component"]
            == "accountauthorization"
        )
        mounts = account["spec"]["template"]["spec"]["containers"][0][
            "volumeMounts"
        ]
        self.assertIn({
            "mountPath": "/run/secrets/files/entitlement-update-keyring.json",
            "name": "service-files",
            "readOnly": True,
            "subPath": "entitlement-update-keyring.json",
        }, mounts)

    def test_wrong_trust_tamper_extra_file_and_v0_downgrade_fail_closed(self) -> None:
        self.build()
        other = Ed25519PrivateKey.generate()
        _, other_public = self.write_keypair("other", other)
        with self.assertRaises((K8S.DeploymentError, OCI.OCIReleaseError)):
            K8S.validate_bundle(
                self.bundle, oci_bundle=self.oci_bundle,
                oci_trusted_public_key=self.oci_public_path,
                expected_oci_signing_key_id="m49-oci-key",
                expected_oci_release_id="m49-oci-release",
                trusted_public_key=other_public,
                expected_signing_key_id="m49-deployment-key",
                expected_deployment_id="m49-pilot")

        unlock_tree(self.bundle)
        extra = self.bundle / "extra"
        extra.write_text("unexpected")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(K8S.DeploymentError, "layout"):
            self.validate()
        unlock_tree(self.bundle)
        extra.unlink()
        receipt = OCI._strict_json(
            (self.bundle / "deployment-receipt.json").read_bytes(), "receipt")
        receipt["schema"] = 1
        self.resign(receipt, b"XIAOZHI-AGENT-KUBERNETES-DEPLOYMENT-V1\x00")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(K8S.DeploymentError, "schema"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
