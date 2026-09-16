from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import kubernetes_admission as ADMISSION
import kubernetes_admission_qualification as QUAL
import kubernetes_deployment as K8S
import oci_release as OCI
from tools.tests import test_kubernetes_admission as M50_FIXTURE


SOURCE_DATE_EPOCH = 1786276800
CLUSTER_SERVER = "https://qualification.k8s.example:6443"
CLUSTER_UID = "11111111-2222-3333-4444-555555555555"
KUBECTL_SHA256 = "a" * 64
TOOL_SHA256 = hashlib.sha256((TOOLS / "kubernetes_admission_qualification.py").read_bytes()).hexdigest()


def unlock_tree(root: pathlib.Path) -> None:
    M50_FIXTURE.unlock_tree(root)


class FakeClient:
    def __init__(self, *, mode: str = "pass") -> None:
        self.mode = mode
        self.objects: dict[tuple[str, str], dict[str, object]] = {}
        self.denials: list[str] = []
        self.delete_calls: list[tuple[str, str]] = []
        self.patch_calls: list[tuple[str, str, bool]] = []
        self.create_calls = 0

    @staticmethod
    def resource_for(kind: str) -> str:
        return {
            "ValidatingAdmissionPolicy": "validatingadmissionpolicy",
            "ValidatingAdmissionPolicyBinding": "validatingadmissionpolicybinding",
            "Namespace": "namespace",
            "PersistentVolumeClaim": "persistentvolumeclaim",
        }[kind]

    @staticmethod
    def uid(name: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))

    def cluster_identity(self) -> dict[str, str]:
        server = "https://wrong.example" if self.mode == "wrong_cluster" else CLUSTER_SERVER
        return {
            "context": "qualification-context",
            "server": server,
            "kube_system_uid": CLUSTER_UID,
            "client_git_version": "v1.36.3",
            "server_git_version": "v1.35.2",
            "server_platform": "linux/amd64",
            "kubectl_sha256": KUBECTL_SHA256,
        }

    def exists(self, resource: str, name: str) -> bool:
        return (resource, name) in self.objects

    def get(self, resource: str, name: str) -> dict[str, object]:
        return copy.deepcopy(self.objects[(resource, name)])

    def apply(self, document: dict[str, object], *, dry_run: bool, expected_count: int) -> int:
        items = document.get("items") if document.get("kind") == "List" else [document]
        if not isinstance(items, list) or len(items) != expected_count:
            raise QUAL.QualificationError("fake apply count mismatch")
        if dry_run:
            return expected_count
        for item in items:
            kind = item["kind"]
            if kind not in {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "Namespace", "PersistentVolumeClaim"}:
                continue
            resource = self.resource_for(kind)
            name = item["metadata"]["name"]
            stored = copy.deepcopy(item)
            stored.setdefault("metadata", {})["uid"] = self.uid(resource + "/" + name)
            if kind == "ValidatingAdmissionPolicy":
                stored["metadata"]["generation"] = 1
                warnings = ([{"fieldRef": "spec.validations[0].expression", "warning": "fixture warning"}]
                            if self.mode == "type_warning" and not any(key[0] == resource for key in self.objects) else [])
                stored["status"] = {"observedGeneration": 1, "typeChecking": {"expressionWarnings": warnings}}
            elif kind == "PersistentVolumeClaim":
                stored["status"] = {"phase": "Pending"}
            self.objects[(resource, name)] = stored
        return expected_count

    def create(self, document: dict[str, object]) -> None:
        self.create_calls += 1
        if self.mode == "create_race" and self.create_calls == 1:
            external = copy.deepcopy(document)
            external["metadata"]["annotations"].pop(QUAL.QUALIFICATION_ANNOTATION, None)
            resource = self.resource_for(external["kind"])
            self.objects[(resource, external["metadata"]["name"])] = external
            raise QUAL.QualificationError("fixture create race")
        self.apply(document, dry_run=False, expected_count=1)

    def expect_denied(self, document: dict[str, object], *, policy_name: str) -> None:
        del document
        if self.mode == "missing_denial" and not self.denials:
            raise QUAL.QualificationError("negative admission request was not denied")
        self.denials.append(policy_name)

    def patch(self, resource: str, name: str, patch: dict[str, object], *, dry_run: bool, expected_policy: str | None = None) -> None:
        del patch
        if not dry_run or (resource, name) not in self.objects:
            raise QUAL.QualificationError("fake patch precondition failed")
        if expected_policy is not None:
            if self.mode == "missing_namespace_denial":
                raise QUAL.QualificationError("negative namespace patch was not denied")
            self.denials.append(expected_policy)
        self.patch_calls.append((resource, name, expected_policy is not None))

    def delete(self, resource: str, name: str) -> None:
        self.delete_calls.append((resource, name))
        if self.mode == "cleanup_failure" and resource == "validatingadmissionpolicybinding":
            raise QUAL.QualificationError("fixture cleanup failure")
        self.objects.pop((resource, name), None)
        if resource == "namespace":
            for key in list(self.objects):
                if key[0] == "persistentvolumeclaim":
                    self.objects.pop(key, None)


class KubernetesAdmissionQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go 1.26.5 is not available")
        self.go = pathlib.Path(go).resolve()
        if OCI._go_version(self.go) != "go1.26.5":
            self.skipTest("tests require pinned Go 1.26.5")
        self.keys = {name: Ed25519PrivateKey.generate() for name in ("oci", "deployment", "admission", "qualification")}
        self.key_paths = {name: self.write_keypair(name, key) for name, key in self.keys.items()}
        self.ca = self.temporary / "ca.pem"
        self.ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nZmFrZS1jYS1mb3ItdGVzdHM=\n-----END CERTIFICATE-----\n")
        self.oci_bundle = self.temporary / "oci"
        self.deployment_bundle = self.temporary / "deployment"
        self.admission_bundle = self.temporary / "admission"
        self.bundle = self.temporary / "qualification"
        OCI.build_release_bundle(
            project_root=PROJECT, go_binary=self.go, ca_bundle_path=self.ca,
            signing_private_key_path=self.key_paths["oci"][0], signing_key_id="m51-oci-key",
            release_id="m51-oci-release", version="0.51.0-test",
            source_date_epoch=SOURCE_DATE_EPOCH, output_path=self.oci_bundle,
            compile_callback=M50_FIXTURE.compile_fixture,
        )
        K8S.build_bundle(
            oci_bundle=self.oci_bundle, oci_trusted_public_key=self.key_paths["oci"][1],
            oci_signing_key_id="m51-oci-key", expected_oci_release_id="m51-oci-release",
            profile_path=PROJECT / "deployment/kubernetes-deployment-profile.example.json",
            signing_private_key_path=self.key_paths["deployment"][0],
            signing_key_id="m51-deployment-key", output_path=self.deployment_bundle,
        )
        ADMISSION.build_bundle(
            deployment_bundle=self.deployment_bundle, oci_bundle=self.oci_bundle,
            oci_trusted_public_key=self.key_paths["oci"][1],
            oci_signing_key_id="m51-oci-key", expected_oci_release_id="m51-oci-release",
            deployment_trusted_public_key=self.key_paths["deployment"][1],
            deployment_signing_key_id="m51-deployment-key", expected_deployment_id="m49-pilot",
            signing_private_key_path=self.key_paths["admission"][0],
            signing_key_id="m51-admission-key", output_path=self.admission_bundle,
        )

    def tearDown(self) -> None:
        for root in (self.bundle, self.oci_bundle, self.deployment_bundle, self.admission_bundle):
            unlock_tree(root)
        shutil.rmtree(self.temporary, ignore_errors=True)

    def write_keypair(self, name: str, key: Ed25519PrivateKey) -> tuple[pathlib.Path, pathlib.Path]:
        private = self.temporary / f"{name}-private.pem"
        public = self.temporary / f"{name}-public.pem"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        return private, public

    def qualification_arguments(self, client: FakeClient, output: pathlib.Path | None = None) -> dict[str, object]:
        return {
            "client": client,
            "admission_bundle": self.admission_bundle,
            "deployment_bundle": self.deployment_bundle,
            "oci_bundle": self.oci_bundle,
            "oci_trusted_public_key": self.key_paths["oci"][1],
            "oci_signing_key_id": "m51-oci-key",
            "expected_oci_release_id": "m51-oci-release",
            "deployment_trusted_public_key": self.key_paths["deployment"][1],
            "deployment_signing_key_id": "m51-deployment-key",
            "expected_deployment_id": "m49-pilot",
            "admission_trusted_public_key": self.key_paths["admission"][1],
            "admission_signing_key_id": "m51-admission-key",
            "qualification_id": "m51-live-fixture",
            "expected_cluster_server": CLUSTER_SERVER,
            "expected_kube_system_uid": CLUSTER_UID,
            "expected_kubectl_sha256": KUBECTL_SHA256,
            "expected_tool_sha256": TOOL_SHA256,
            "signing_private_key_path": self.key_paths["qualification"][0],
            "signing_key_id": "m51-qualification-key",
            "output_path": output or self.bundle,
            "typecheck_timeout_seconds": 5,
        }

    def validate(self, public_key: pathlib.Path | None = None) -> dict[str, object]:
        return QUAL.validate_bundle(
            self.bundle, admission_bundle=self.admission_bundle,
            deployment_bundle=self.deployment_bundle, oci_bundle=self.oci_bundle,
            oci_trusted_public_key=self.key_paths["oci"][1],
            expected_oci_signing_key_id="m51-oci-key",
            expected_oci_release_id="m51-oci-release",
            deployment_trusted_public_key=self.key_paths["deployment"][1],
            expected_deployment_signing_key_id="m51-deployment-key",
            expected_deployment_id="m49-pilot",
            admission_trusted_public_key=self.key_paths["admission"][1],
            expected_admission_signing_key_id="m51-admission-key",
            trusted_public_key=public_key or self.key_paths["qualification"][1],
            expected_signing_key_id="m51-qualification-key",
            expected_qualification_id="m51-live-fixture",
            expected_cluster_server=CLUSTER_SERVER,
            expected_kube_system_uid=CLUSTER_UID,
            expected_kubectl_sha256=KUBECTL_SHA256,
            expected_tool_sha256=TOOL_SHA256,
        )

    def resign(self, receipt: dict[str, object], domain: bytes | None = None) -> None:
        unsigned = dict(receipt)
        unsigned.pop("signature_b64url", None)
        receipt["signature_b64url"] = OCI._b64url(self.keys["qualification"].sign((domain or QUAL.SIGNATURE_DOMAIN) + OCI._compact_bytes(unsigned)))
        data = OCI._json_bytes(receipt)
        (self.bundle / "qualification-receipt.json").write_bytes(data)
        (self.bundle / "READY").write_text(hashlib.sha256(data).hexdigest() + "\n")

    def test_live_fixture_builds_strict_signed_receipt_and_cleans_scope(self) -> None:
        client = FakeClient()
        receipt = QUAL.qualify(**self.qualification_arguments(client))
        self.assertEqual(self.validate(), receipt)
        evidence = OCI._strict_json((self.bundle / "evidence.json").read_bytes(), "evidence")
        self.assertEqual(evidence["result"], "LIVE_API_SERVER_PASS")
        self.assertEqual(len(evidence["policy_type_checking"]), 10)
        self.assertEqual(len(evidence["binding_status"]), 10)
        self.assertEqual([item["category"] for item in evidence["negative_tests"]], list(QUAL.NEGATIVE_CATEGORIES))
        self.assertEqual(len(client.denials), 10)
        self.assertEqual(client.objects, {})
        self.assertEqual(evidence["cleanup"], {"bindings_absent": True, "namespace_absent": True, "policies_absent": True})

    def test_cluster_mismatch_and_preexisting_scope_refuse_before_mutation(self) -> None:
        wrong_tool = FakeClient()
        tool_arguments = self.qualification_arguments(wrong_tool)
        tool_arguments["expected_tool_sha256"] = "b" * 64
        with self.assertRaisesRegex(QUAL.QualificationError, "tool digest"):
            QUAL.qualify(**tool_arguments)
        self.assertFalse(wrong_tool.delete_calls)
        wrong = FakeClient(mode="wrong_cluster")
        with self.assertRaisesRegex(QUAL.QualificationError, "identity"):
            QUAL.qualify(**self.qualification_arguments(wrong))
        self.assertFalse(wrong.delete_calls)
        self.assertFalse(self.bundle.exists())
        existing = FakeClient()
        existing.objects[("namespace", "xiaozhi-agent")] = {"metadata": {"name": "xiaozhi-agent"}}
        with self.assertRaisesRegex(QUAL.QualificationError, "pre-existing"):
            QUAL.qualify(**self.qualification_arguments(existing))
        self.assertFalse(existing.delete_calls)
        self.assertIn(("namespace", "xiaozhi-agent"), existing.objects)

    def test_type_warning_and_missing_denial_fail_and_cleanup_without_pass(self) -> None:
        for mode, message in (("type_warning", "type-check warnings"), ("missing_denial", "not denied"), ("missing_namespace_denial", "not denied")):
            with self.subTest(mode=mode):
                client = FakeClient(mode=mode)
                with self.assertRaisesRegex(QUAL.QualificationError, message):
                    QUAL.qualify(**self.qualification_arguments(client))
                self.assertEqual(client.objects, {})
                self.assertFalse(self.bundle.exists())

    def test_cleanup_failure_never_emits_pass_bundle(self) -> None:
        client = FakeClient(mode="cleanup_failure")
        with self.assertRaisesRegex(QUAL.QualificationError, "cleanup"):
            QUAL.qualify(**self.qualification_arguments(client))
        self.assertFalse(self.bundle.exists())

    def test_ambiguous_create_race_never_deletes_unowned_object(self) -> None:
        client = FakeClient(mode="create_race")
        with self.assertRaisesRegex(QUAL.QualificationError, "cleanup"):
            QUAL.qualify(**self.qualification_arguments(client))
        self.assertFalse(client.delete_calls)
        self.assertEqual(len(client.objects), 1)
        remaining = next(iter(client.objects.values()))
        self.assertNotIn(QUAL.QUALIFICATION_ANNOTATION, remaining["metadata"]["annotations"])
        self.assertFalse(self.bundle.exists())

    def test_crash_recovery_deletes_only_exact_qualification_ownership(self) -> None:
        client = FakeClient()
        admission_document = OCI._strict_json((self.admission_bundle / "admission.json").read_bytes(), "admission")
        profile = K8S.load_profile(self.deployment_bundle / "profile.json")[0]
        prerequisites = OCI._strict_json((self.deployment_bundle / "prerequisites.json").read_bytes(), "prerequisites")
        for document in (
            admission_document["items"][0], admission_document["items"][1],
            QUAL.build_namespace(profile, prerequisites),
        ):
            client.create(QUAL._owned_document(document, "m51-live-fixture"))

        def recover(qualification_id: str) -> dict[str, object]:
            return QUAL.recover_cleanup(
                client=client, admission_bundle=self.admission_bundle,
                deployment_bundle=self.deployment_bundle, oci_bundle=self.oci_bundle,
                oci_trusted_public_key=self.key_paths["oci"][1],
                oci_signing_key_id="m51-oci-key", expected_oci_release_id="m51-oci-release",
                deployment_trusted_public_key=self.key_paths["deployment"][1],
                deployment_signing_key_id="m51-deployment-key", expected_deployment_id="m49-pilot",
                admission_trusted_public_key=self.key_paths["admission"][1],
                admission_signing_key_id="m51-admission-key",
                qualification_id=qualification_id, expected_cluster_server=CLUSTER_SERVER,
                expected_kube_system_uid=CLUSTER_UID,
                expected_kubectl_sha256=KUBECTL_SHA256, expected_tool_sha256=TOOL_SHA256,
            )

        with self.assertRaisesRegex(QUAL.QualificationError, "unowned"):
            recover("different-qualification")
        self.assertEqual(len(client.objects), 3)
        result = recover("m51-live-fixture")
        self.assertEqual(result["result"], "OWNED_SCOPE_ABSENT")
        self.assertEqual(client.objects, {})

    def test_document_builders_cover_exact_live_positive_and_negative_sets(self) -> None:
        profile = K8S.load_profile(self.deployment_bundle / "profile.json")[0]
        kubernetes = OCI._strict_json((self.deployment_bundle / "kubernetes.json").read_bytes(), "kubernetes")
        prerequisites = OCI._strict_json((self.deployment_bundle / "prerequisites.json").read_bytes(), "prerequisites")
        external = QUAL.build_prerequisite_list(profile, prerequisites, "m51-live-fixture")
        pods = QUAL.build_pod_list(profile, kubernetes)
        negatives = QUAL.build_negative_documents(profile, kubernetes, external, pods, "m51-live-fixture")
        self.assertEqual(len(external["items"]), 25)
        self.assertEqual(len(pods["items"]), 7)
        self.assertEqual(tuple(item[0] for item in negatives), QUAL.NEGATIVE_CATEGORIES[:-1])
        self.assertFalse(any("stringData" in item for item in external["items"]))
        self.assertTrue(all(item.get("immutable") is True for item in external["items"] if item["kind"] in {"ConfigMap", "Secret"}))
        receipt_schema = OCI._strict_json((PROJECT / "deployment/kubernetes-admission-qualification-receipt.schema.json").read_bytes(), "receipt schema")
        evidence_schema = OCI._strict_json((PROJECT / "deployment/kubernetes-admission-qualification-evidence.schema.json").read_bytes(), "evidence schema")
        self.assertEqual(receipt_schema["properties"]["result"], {"const": "LIVE_API_SERVER_PASS"})
        self.assertEqual((evidence_schema["properties"]["negative_tests"]["minItems"], evidence_schema["properties"]["negative_tests"]["maxItems"]), (10, 10))

    def test_validly_resigned_evidence_tamper_is_rejected(self) -> None:
        QUAL.qualify(**self.qualification_arguments(FakeClient()))
        unlock_tree(self.bundle)
        evidence_path = self.bundle / "evidence.json"
        evidence = OCI._strict_json(evidence_path.read_bytes(), "evidence")
        evidence["cleanup"]["namespace_absent"] = False
        evidence_data = OCI._json_bytes(evidence)
        evidence_path.write_bytes(evidence_data)
        receipt = OCI._strict_json((self.bundle / "qualification-receipt.json").read_bytes(), "receipt")
        receipt["evidence_sha256"] = hashlib.sha256(evidence_data).hexdigest()
        self.resign(receipt)
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(QUAL.QualificationError, "cleanup"):
            self.validate()

    def test_wrong_trust_extra_file_and_v0_domain_fail_closed(self) -> None:
        QUAL.qualify(**self.qualification_arguments(FakeClient()))
        other = Ed25519PrivateKey.generate()
        _, other_public = self.write_keypair("other", other)
        with self.assertRaises(QUAL.QualificationError):
            self.validate(other_public)
        unlock_tree(self.bundle)
        (self.bundle / "extra").write_text("unexpected")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(QUAL.QualificationError, "layout"):
            self.validate()
        unlock_tree(self.bundle)
        (self.bundle / "extra").unlink()
        receipt = OCI._strict_json((self.bundle / "qualification-receipt.json").read_bytes(), "receipt")
        receipt["schema"] = 0
        self.resign(receipt, b"XIAOZHI-AGENT-KUBERNETES-ADMISSION-QUALIFICATION-V0\x00")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(QUAL.QualificationError, "schema"):
            self.validate()

    def test_kubectl_client_pins_context_server_uid_version_and_binary(self) -> None:
        kubectl = self.temporary / "kubectl"
        kubectl.write_text("#!/bin/sh\nexit 99\n")
        os.chmod(kubectl, 0o700)
        kubeconfig = self.temporary / "kubeconfig"
        kubeconfig.write_text("apiVersion: v1\nkind: Config\n")
        os.chmod(kubeconfig, 0o600)
        calls: list[list[str]] = []

        def execute(arguments: list[str], input_data: bytes | None, timeout: int) -> QUAL.CommandResult:
            del input_data, timeout
            calls.append(arguments)
            if "config" in arguments:
                return QUAL.CommandResult(0, json.dumps({"clusters": [{"cluster": {"server": CLUSTER_SERVER}}]}), "")
            if "version" in arguments:
                return QUAL.CommandResult(0, json.dumps({"clientVersion": {"gitVersion": "v1.36.3"}, "serverVersion": {"gitVersion": "v1.35.2", "platform": "linux/amd64"}}), "")
            if "api-resources" in arguments:
                return QUAL.CommandResult(0, "validatingadmissionpolicies.admissionregistration.k8s.io\nvalidatingadmissionpolicybindings.admissionregistration.k8s.io\n", "")
            return QUAL.CommandResult(0, json.dumps({"metadata": {"uid": CLUSTER_UID}}), "")

        client = QUAL.KubectlClient(kubectl=kubectl, kubeconfig=kubeconfig, context="qualification-context", executor=execute)
        identity = client.cluster_identity()
        client.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "client-contract"}})
        client.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "client-contract"}}, dry_run=True, expected_count=1)
        self.assertEqual(identity["server"], CLUSTER_SERVER)
        self.assertEqual(identity["kube_system_uid"], CLUSTER_UID)
        self.assertEqual(identity["kubectl_sha256"], hashlib.sha256(kubectl.read_bytes()).hexdigest())
        self.assertTrue(all("--kubeconfig" in call and "--context" in call and "--request-timeout=30s" in call for call in calls))
        self.assertFalse(any("--token" in call for call in calls))
        create_call = next(call for call in calls if "create" in call)
        dry_run_call = next(call for call in calls if "apply" in call)
        self.assertIn("--validate=strict", create_call)
        self.assertIn("--warnings-as-errors", create_call)
        self.assertIn("--server-side", dry_run_call)
        self.assertIn("--dry-run=server", dry_run_call)
        cli_source = (PROJECT / "tools/qualify_kubernetes_admission.py").read_text()
        self.assertIn("--execute-live-qualification", cli_source)
        self.assertNotIn("--token", cli_source)


if __name__ == "__main__":
    unittest.main()
