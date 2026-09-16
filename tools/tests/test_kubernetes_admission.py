from __future__ import annotations

import copy
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
import kubernetes_admission as ADMISSION
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


class KubernetesAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go 1.26.5 is not available")
        self.go = pathlib.Path(go).resolve()
        if OCI._go_version(self.go) != "go1.26.5":
            self.skipTest("tests require pinned Go 1.26.5")
        self.oci_private = Ed25519PrivateKey.generate()
        self.deployment_private = Ed25519PrivateKey.generate()
        self.admission_private = Ed25519PrivateKey.generate()
        self.oci_private_path, self.oci_public_path = self.write_keypair("oci", self.oci_private)
        self.deployment_private_path, self.deployment_public_path = self.write_keypair("deployment", self.deployment_private)
        self.admission_private_path, self.admission_public_path = self.write_keypair("admission", self.admission_private)
        self.ca_path = self.temporary / "ca.pem"
        self.ca_path.write_bytes(b"-----BEGIN CERTIFICATE-----\nZmFrZS1jYS1mb3ItdGVzdHM=\n-----END CERTIFICATE-----\n")
        self.oci_bundle = self.temporary / "oci"
        self.deployment_bundle = self.temporary / "deployment"
        self.bundle = self.temporary / "admission"
        OCI.build_release_bundle(
            project_root=PROJECT, go_binary=self.go, ca_bundle_path=self.ca_path,
            signing_private_key_path=self.oci_private_path,
            signing_key_id="m50-oci-key", release_id="m50-oci-release",
            version="0.50.0-test", source_date_epoch=SOURCE_DATE_EPOCH,
            output_path=self.oci_bundle, compile_callback=compile_fixture,
        )
        K8S.build_bundle(
            oci_bundle=self.oci_bundle, oci_trusted_public_key=self.oci_public_path,
            oci_signing_key_id="m50-oci-key", expected_oci_release_id="m50-oci-release",
            profile_path=PROJECT / "deployment/kubernetes-deployment-profile.example.json",
            signing_private_key_path=self.deployment_private_path,
            signing_key_id="m50-deployment-key", output_path=self.deployment_bundle,
        )

    def tearDown(self) -> None:
        for root in (self.bundle, self.temporary / "admission-2", self.deployment_bundle, self.oci_bundle):
            unlock_tree(root)
        shutil.rmtree(self.temporary, ignore_errors=True)

    def write_keypair(self, prefix: str, key: Ed25519PrivateKey) -> tuple[pathlib.Path, pathlib.Path]:
        private_path = self.temporary / f"{prefix}-private.pem"
        public_path = self.temporary / f"{prefix}-public.pem"
        private_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        public_path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return private_path, public_path

    def build(self, output: pathlib.Path | None = None) -> dict[str, object]:
        return ADMISSION.build_bundle(
            deployment_bundle=self.deployment_bundle, oci_bundle=self.oci_bundle,
            oci_trusted_public_key=self.oci_public_path,
            oci_signing_key_id="m50-oci-key", expected_oci_release_id="m50-oci-release",
            deployment_trusted_public_key=self.deployment_public_path,
            deployment_signing_key_id="m50-deployment-key", expected_deployment_id="m49-pilot",
            signing_private_key_path=self.admission_private_path,
            signing_key_id="m50-admission-key", output_path=output or self.bundle,
        )

    def validate(self, trusted_public_key: pathlib.Path | None = None) -> dict[str, object]:
        return ADMISSION.validate_bundle(
            self.bundle, deployment_bundle=self.deployment_bundle,
            oci_bundle=self.oci_bundle, oci_trusted_public_key=self.oci_public_path,
            expected_oci_signing_key_id="m50-oci-key",
            expected_oci_release_id="m50-oci-release",
            deployment_trusted_public_key=self.deployment_public_path,
            expected_deployment_signing_key_id="m50-deployment-key",
            expected_deployment_id="m49-pilot",
            trusted_public_key=trusted_public_key or self.admission_public_path,
            expected_signing_key_id="m50-admission-key",
        )

    def resign(self, receipt: dict[str, object], domain: bytes | None = None) -> None:
        unsigned = dict(receipt)
        unsigned.pop("signature_b64url", None)
        payload = (domain or ADMISSION.SIGNATURE_DOMAIN) + OCI._compact_bytes(unsigned)
        receipt["signature_b64url"] = OCI._b64url(self.admission_private.sign(payload))
        data = OCI._json_bytes(receipt)
        (self.bundle / "admission-receipt.json").write_bytes(data)
        (self.bundle / "READY").write_text(hashlib.sha256(data).hexdigest() + "\n")

    def source_documents(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        profile = K8S.load_profile(self.deployment_bundle / "profile.json")[0]
        kubernetes = OCI._strict_json((self.deployment_bundle / "kubernetes.json").read_bytes(), "kubernetes")
        prerequisites = OCI._strict_json((self.deployment_bundle / "prerequisites.json").read_bytes(), "prerequisites")
        return profile, kubernetes, prerequisites

    def test_builds_exact_stable_fail_closed_policy_inventory(self) -> None:
        receipt = self.build()
        self.assertEqual(self.validate(), receipt)
        resources = OCI._strict_json((self.bundle / "admission.json").read_bytes(), "admission")
        self.assertEqual(len(resources["items"]), 20)
        policies = [item for item in resources["items"] if item["kind"] == "ValidatingAdmissionPolicy"]
        bindings = [item for item in resources["items"] if item["kind"] == "ValidatingAdmissionPolicyBinding"]
        self.assertEqual((len(policies), len(bindings)), (10, 10))
        self.assertTrue(all(item["apiVersion"] == "admissionregistration.k8s.io/v1" for item in resources["items"]))
        self.assertTrue(all(item["spec"]["failurePolicy"] == "Fail" for item in policies))
        self.assertTrue(all(item["spec"]["validationActions"] == ["Deny", "Audit"] for item in bindings))
        namespaced = [item for item in bindings if "namespace" not in item["metadata"]["name"]]
        self.assertTrue(all(item["spec"]["matchResources"]["namespaceSelector"]["matchLabels"] == {"xiaozhi-agent/deployment-id": "m49-pilot"} for item in namespaced))

    def test_same_inputs_are_byte_for_byte_reproducible(self) -> None:
        self.build()
        second = self.temporary / "admission-2"
        second_receipt = self.build(second)
        self.assertEqual(tree_digest(self.bundle), tree_digest(second))
        self.assertEqual(self.validate(), second_receipt)

    def test_validly_resigned_policy_tamper_is_rejected(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        path = self.bundle / "admission.json"
        resources = OCI._strict_json(path.read_bytes(), "admission")
        policy = next(item for item in resources["items"] if item["kind"] == "ValidatingAdmissionPolicy")
        policy["spec"]["failurePolicy"] = "Ignore"
        data = OCI._json_bytes(resources)
        path.write_bytes(data)
        receipt = OCI._strict_json((self.bundle / "admission-receipt.json").read_bytes(), "receipt")
        receipt["admission_sha256"] = hashlib.sha256(data).hexdigest()
        self.resign(receipt)
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "fail closed"):
            self.validate()

    def test_policy_downgrade_scope_escape_and_binding_weakening_are_rejected(self) -> None:
        mutations = (
            (lambda document: document["items"][0].__setitem__("apiVersion", "admissionregistration.k8s.io/v1beta1"), "stable"),
            (lambda document: document["items"][1]["spec"].__setitem__("validationActions", ["Audit"]), "deny and audit"),
            (lambda document: document["items"][0]["spec"].__setitem__("matchConditions", []), "exact scope"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                profile, kubernetes, prerequisites = self.source_documents()
                deployment_sha = hashlib.sha256((self.deployment_bundle / "deployment-receipt.json").read_bytes()).hexdigest()
                document = ADMISSION.build_admission_list(profile, kubernetes, prerequisites, deployment_sha)
                mutate(document)
                with self.assertRaisesRegex(ADMISSION.AdmissionError, message):
                    ADMISSION.validate_admission_document(document, profile, deployment_sha)

    def test_local_exact_oracle_denies_workload_network_and_namespace_mutations(self) -> None:
        profile, kubernetes, prerequisites = self.source_documents()
        lookup = {(item["kind"], item["metadata"]["name"]): item for item in kubernetes["items"]}
        deployment_resource = copy.deepcopy(lookup[("Deployment", "m49-pilot-gateway")])
        self.assertTrue(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", deployment_resource))
        deployment_resource["spec"]["replicas"] = 2
        self.assertFalse(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", deployment_resource))
        network = copy.deepcopy(lookup[("NetworkPolicy", "m49-pilot-gateway-egress")])
        network["spec"]["egress"][0]["to"] = [{"ipBlock": {"cidr": "0.0.0.0/0"}}]
        self.assertFalse(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", network))
        required_labels = next(item["required_labels"] for item in prerequisites["objects"] if item.get("purpose") == "workload")
        namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": profile["namespace"], "labels": dict(required_labels)}}
        self.assertTrue(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", namespace))
        del namespace["metadata"]["labels"]["xiaozhi-agent/deployment-id"]
        self.assertFalse(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "UPDATE", namespace, namespace))
        pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": profile["storage_claims"]["generation_state"], "namespace": profile["namespace"]}, "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}
        self.assertTrue(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", pvc))
        bound = copy.deepcopy(pvc)
        bound["spec"]["volumeName"] = "pvc-bound-once"
        self.assertTrue(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "UPDATE", bound, pvc))
        resized = copy.deepcopy(bound)
        resized["spec"]["resources"]["requests"]["storage"] = "2Gi"
        self.assertFalse(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "UPDATE", resized, bound))

    def test_local_exact_oracle_denies_pod_image_privilege_and_extra_objects(self) -> None:
        profile, kubernetes, prerequisites = self.source_documents()
        workload = next(item for item in kubernetes["items"] if item["kind"] == "Deployment" and item["metadata"]["name"] == "m49-pilot-agentproxy")
        template = workload["spec"]["template"]
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "agentproxy-test", "namespace": profile["namespace"], "labels": dict(template["metadata"]["labels"])}, "spec": copy.deepcopy(template["spec"])}
        self.assertTrue(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", pod))
        self.assertTrue(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "DELETE", pod))
        pod["spec"]["containers"][0]["image"] = "registry.example/agentproxy:latest"
        pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
        self.assertFalse(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", pod))
        extra = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "manual-extra", "namespace": profile["namespace"]}, "immutable": True, "data": {}}
        self.assertFalse(ADMISSION.semantic_allows(profile, kubernetes, prerequisites, "CREATE", extra))

    def test_config_secret_inventory_and_receipt_schema_are_fixed(self) -> None:
        self.build()
        document = OCI._strict_json((self.bundle / "admission.json").read_bytes(), "admission")
        config_policy = next(item for item in document["items"] if item["kind"] == "ValidatingAdmissionPolicy" and "-configmaps." in item["metadata"]["name"])
        secret_policy = next(item for item in document["items"] if item["kind"] == "ValidatingAdmissionPolicy" and "-secrets." in item["metadata"]["name"])
        self.assertIn("object.immutable == true", config_policy["spec"]["validations"][-1]["expression"])
        self.assertIn("object.immutable == true", secret_policy["spec"]["validations"][-1]["expression"])
        self.assertIn(".dockerconfigjson", secret_policy["spec"]["validations"][-1]["expression"])
        schema = OCI._strict_json((PROJECT / "deployment/kubernetes-admission-receipt.schema.json").read_bytes(), "schema")
        self.assertTrue(schema["$id"].endswith("kubernetes-admission-receipt-v1.json"))
        self.assertEqual(schema["properties"]["resource_count"], {"const": 20})

    def test_wrong_trust_extra_file_and_v0_downgrade_fail_closed(self) -> None:
        self.build()
        other = Ed25519PrivateKey.generate()
        _, other_public = self.write_keypair("other", other)
        with self.assertRaises(ADMISSION.AdmissionError):
            self.validate(other_public)
        unlock_tree(self.bundle)
        (self.bundle / "extra").write_text("unexpected")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "layout"):
            self.validate()
        unlock_tree(self.bundle)
        (self.bundle / "extra").unlink()
        receipt = OCI._strict_json((self.bundle / "admission-receipt.json").read_bytes(), "receipt")
        receipt["schema"] = 0
        self.resign(receipt, b"XIAOZHI-AGENT-KUBERNETES-ADMISSION-V0\x00")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(ADMISSION.AdmissionError, "schema"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
