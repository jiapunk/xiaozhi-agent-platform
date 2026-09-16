#!/usr/bin/env python3
"""Live kube-apiserver qualification for a signed M50 admission bundle."""

from __future__ import annotations

import base64
import copy
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

import kubernetes_admission as admission
import kubernetes_deployment as deployment
import oci_release as oci


SCHEMA_VERSION = 1
SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-KUBERNETES-ADMISSION-QUALIFICATION-V1\x00"
RESULT = "LIVE_API_SERVER_PASS"
FIELD_MANAGER = "xiaozhi-agent-admission-qualification"
QUALIFICATION_ANNOTATION = "xiaozhi-agent/qualification-id"
NEGATIVE_CATEGORIES = admission.CATEGORIES
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
GIT_VERSION = re.compile(r"^v1\.([0-9]{1,3})\.[0-9]{1,3}(?:[-+][0-9A-Za-z.-]+)?$")
MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
MAX_TOOL_BYTES = 2 * 1024 * 1024


class QualificationError(ValueError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Executor = Callable[[list[str], Optional[bytes], int], CommandResult]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _signature_payload(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("signature_b64url", None)
    return SIGNATURE_DOMAIN + oci._compact_bytes(unsigned)


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise QualificationError(f"{label} is not a canonical identifier")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise QualificationError(f"{label} is not a SHA-256 digest")
    return value


def _uid(value: object, label: str) -> str:
    if not isinstance(value, str) or not UID.fullmatch(value):
        raise QualificationError(f"{label} is not a canonical Kubernetes UID")
    return value


def _cluster_server(value: object) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise QualificationError("cluster server is invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise QualificationError("cluster server must be an exact credential-free HTTPS authority")
    return value[:-1] if value.endswith("/") else value


def _git_version(value: object, label: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise QualificationError(f"{label} is invalid")
    matched = GIT_VERSION.fullmatch(value)
    if matched is None:
        raise QualificationError(f"{label} is not a canonical Kubernetes v1 version")
    minor = int(matched.group(1))
    if minor < 30:
        raise QualificationError(f"{label} is older than Kubernetes 1.30")
    return value, minor


def _json_object(data: str, label: str) -> dict[str, Any]:
    if not data or len(data.encode("utf-8")) > MAX_COMMAND_OUTPUT:
        raise QualificationError(f"{label} output size is invalid")
    try:
        value = json.loads(data)
    except json.JSONDecodeError as error:
        raise QualificationError(f"{label} did not return JSON") from error
    if not isinstance(value, dict):
        raise QualificationError(f"{label} did not return an object")
    return value


def _default_executor(arguments: list[str], input_data: bytes | None, timeout_seconds: int) -> CommandResult:
    try:
        completed = subprocess.run(
            arguments, input=input_data, capture_output=True, check=False,
            timeout=timeout_seconds, env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationError("kubectl execution failed or timed out") from error
    if len(completed.stdout) > MAX_COMMAND_OUTPUT or len(completed.stderr) > MAX_COMMAND_OUTPUT:
        raise QualificationError("kubectl output exceeded the qualification bound")
    try:
        stdout = completed.stdout.decode("utf-8")
        stderr = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationError("kubectl output is not UTF-8") from error
    return CommandResult(completed.returncode, stdout, stderr)


class KubectlClient:
    def __init__(
        self, *, kubectl: Path, kubeconfig: Path, context: str,
        request_timeout_seconds: int = 30, executor: Executor = _default_executor,
    ) -> None:
        if kubectl.is_symlink():
            raise QualificationError("kubectl path must not be a symlink")
        resolved = kubectl.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise QualificationError("kubectl must resolve to an executable regular file")
        if resolved.stat().st_size > 256 * 1024 * 1024:
            raise QualificationError("kubectl exceeds the qualification size bound")
        if not kubeconfig.is_file() or kubeconfig.is_symlink() or kubeconfig.stat().st_size > 1024 * 1024:
            raise QualificationError("kubeconfig must be a bounded non-symlink regular file")
        if kubeconfig.stat().st_mode & 0o077:
            raise QualificationError("kubeconfig must not be group/world accessible")
        self.kubectl = resolved
        self.kubeconfig = kubeconfig.resolve(strict=True)
        self.context = _identifier(context, "Kubernetes context")
        if not 5 <= request_timeout_seconds <= 120:
            raise QualificationError("kubectl request timeout must be 5 through 120 seconds")
        self.request_timeout_seconds = request_timeout_seconds
        self.executor = executor

    @property
    def binary_sha256(self) -> str:
        return oci._sha256(oci._read_regular(self.kubectl, 256 * 1024 * 1024, "kubectl"))

    def _run(self, arguments: list[str], input_data: bytes | None = None, *, check: bool = True, timeout: int | None = None) -> CommandResult:
        command = [
            str(self.kubectl), "--kubeconfig", str(self.kubeconfig),
            "--context", self.context,
            f"--request-timeout={self.request_timeout_seconds}s",
            *arguments,
        ]
        result = self.executor(command, input_data, timeout or self.request_timeout_seconds + 10)
        if check and result.returncode != 0:
            detail = " ".join((result.stderr or result.stdout).strip().split())[:500]
            raise QualificationError(f"kubectl command failed: {detail or 'no diagnostic'}")
        return result

    def cluster_identity(self) -> dict[str, str]:
        config = _json_object(
            self._run(["config", "view", "--minify", "--output=json"]).stdout,
            "kubectl config view",
        )
        clusters = config.get("clusters")
        if not isinstance(clusters, list) or len(clusters) != 1:
            raise QualificationError("selected context does not resolve to one cluster")
        server = _cluster_server(clusters[0].get("cluster", {}).get("server"))
        version = _json_object(self._run(["version", "--output=json"]).stdout, "kubectl version")
        client_version, _ = _git_version(version.get("clientVersion", {}).get("gitVersion"), "kubectl client version")
        server_version, _ = _git_version(version.get("serverVersion", {}).get("gitVersion"), "Kubernetes server version")
        platform = version.get("serverVersion", {}).get("platform")
        if not isinstance(platform, str) or not re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", platform):
            raise QualificationError("Kubernetes server platform is invalid")
        kube_system = _json_object(
            self._run(["get", "namespace", "kube-system", "--output=json"]).stdout,
            "kube-system namespace",
        )
        kube_system_uid = _uid(kube_system.get("metadata", {}).get("uid"), "kube-system UID")
        resources = set(
            line.strip() for line in self._run([
                "api-resources", "--api-group=admissionregistration.k8s.io", "--output=name",
            ]).stdout.splitlines() if line.strip()
        )
        required = {
            "validatingadmissionpolicies.admissionregistration.k8s.io",
            "validatingadmissionpolicybindings.admissionregistration.k8s.io",
        }
        if not required.issubset(resources):
            raise QualificationError("cluster does not expose stable ValidatingAdmissionPolicy resources")
        return {
            "context": self.context,
            "server": server,
            "kube_system_uid": kube_system_uid,
            "client_git_version": client_version,
            "server_git_version": server_version,
            "server_platform": platform,
            "kubectl_sha256": self.binary_sha256,
        }

    def exists(self, resource: str, name: str) -> bool:
        result = self._run([
            "get", resource, name, "--ignore-not-found=true", "--output=json",
        ])
        if not result.stdout.strip():
            return False
        value = _json_object(result.stdout, f"{resource}/{name}")
        return value.get("metadata", {}).get("name") == name

    def get(self, resource: str, name: str) -> dict[str, Any]:
        return _json_object(
            self._run(["get", resource, name, "--output=json"]).stdout,
            f"{resource}/{name}",
        )

    def apply(self, document: dict[str, Any], *, dry_run: bool, expected_count: int) -> int:
        arguments = [
            "apply", "--server-side", f"--field-manager={FIELD_MANAGER}",
            "--validate=strict", "--warnings-as-errors",
        ]
        if dry_run:
            arguments.append("--dry-run=server")
        arguments.extend(["--filename=-", "--output=name"])
        result = self._run(arguments, oci._json_bytes(document), timeout=120)
        count = len([line for line in result.stdout.splitlines() if line.strip()])
        if count != expected_count:
            raise QualificationError(f"kubectl applied {count} resources, expected {expected_count}")
        return count

    def create(self, document: dict[str, Any]) -> None:
        result = self._run([
            "create", f"--field-manager={FIELD_MANAGER}", "--validate=strict",
            "--warnings-as-errors", "--filename=-", "--output=name",
        ], oci._json_bytes(document), check=False, timeout=120)
        count = len([line for line in result.stdout.splitlines() if line.strip()])
        if result.returncode != 0 or count != 1:
            detail = " ".join((result.stderr or result.stdout).strip().split())[:500]
            raise QualificationError(f"kubectl create failed: {detail or 'ambiguous create result'}")

    def expect_denied(self, document: dict[str, Any], *, policy_name: str) -> None:
        result = self._run([
            "apply", "--server-side", f"--field-manager={FIELD_MANAGER}",
            "--validate=strict", "--warnings-as-errors", "--dry-run=server",
            "--filename=-", "--output=name",
        ], oci._json_bytes(document), check=False, timeout=120)
        diagnostic = result.stderr + "\n" + result.stdout
        if result.returncode == 0 or policy_name not in diagnostic or "denied" not in diagnostic.lower():
            raise QualificationError(f"negative admission request was not denied by {policy_name}")

    def patch(self, resource: str, name: str, patch: dict[str, Any], *, dry_run: bool, expected_policy: str | None = None) -> None:
        arguments = [
            "patch", resource, name, "--type=merge",
            "--patch=" + oci._compact_bytes(patch).decode("utf-8"),
            "--output=name", "--warnings-as-errors",
        ]
        if dry_run:
            arguments.append("--dry-run=server")
        result = self._run(arguments, check=False)
        if expected_policy is None:
            if result.returncode != 0 or len([line for line in result.stdout.splitlines() if line.strip()]) != 1:
                raise QualificationError(f"positive patch failed for {resource}/{name}")
            return
        diagnostic = result.stderr + "\n" + result.stdout
        if result.returncode == 0 or expected_policy not in diagnostic or "denied" not in diagnostic.lower():
            raise QualificationError(f"negative patch was not denied by {expected_policy}")

    def delete(self, resource: str, name: str) -> None:
        self._run([
            "delete", resource, name, "--ignore-not-found=true", "--wait=true",
            "--timeout=120s",
        ], timeout=130)


def _resource_map(kubernetes: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(item["kind"], item["metadata"]["name"]): item for item in kubernetes["items"]}


def _owned_document(document: dict[str, Any], qualification_id: str) -> dict[str, Any]:
    result = copy.deepcopy(document)
    metadata = result.setdefault("metadata", {})
    annotations = metadata.setdefault("annotations", {})
    if QUALIFICATION_ANNOTATION in annotations:
        raise QualificationError("signed resource already uses the qualification ownership annotation")
    annotations[QUALIFICATION_ANNOTATION] = qualification_id
    return result


def build_namespace(profile: dict[str, Any], prerequisites: dict[str, Any]) -> dict[str, Any]:
    record = next(
        item for item in prerequisites["objects"]
        if item["kind"] == "Namespace" and item["name"] == profile["namespace"]
    )
    return {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"labels": record["required_labels"], "name": profile["namespace"]},
    }


def build_prerequisite_list(
    profile: dict[str, Any], prerequisites: dict[str, Any], qualification_id: str,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    selector_value = oci._sha256(qualification_id.encode("utf-8"))[:16]
    for record in prerequisites["objects"]:
        if record.get("namespace") != profile["namespace"]:
            continue
        metadata = {"name": record["name"], "namespace": profile["namespace"]}
        if record["kind"] == "ConfigMap":
            items.append({
                "apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata,
                "immutable": True,
                "data": {key: "qualification-placeholder" for key in record["required_keys"]},
            })
        elif record["kind"] == "Secret":
            data = {
                key: base64.b64encode(b"qualification-placeholder").decode("ascii")
                for key in record["required_keys"]
            }
            if record["type"] == "kubernetes.io/dockerconfigjson":
                data[".dockerconfigjson"] = base64.b64encode(b'{"auths":{}}').decode("ascii")
            items.append({
                "apiVersion": "v1", "kind": "Secret", "metadata": metadata,
                "immutable": True, "type": record["type"], "data": data,
            })
        elif record["kind"] == "PersistentVolumeClaim":
            items.append({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": metadata,
                "spec": {
                    "accessModes": ["ReadWriteOnce"], "storageClassName": "",
                    "selector": {"matchLabels": {"xiaozhi-agent.io/qualification-never-bind": selector_value}},
                    "resources": {"requests": {"storage": "1Mi"}},
                },
            })
    if len(items) != 25:
        raise QualificationError("qualification prerequisites must contain 7 ConfigMaps, 15 Secrets and 3 PVCs")
    return {"apiVersion": "v1", "items": items, "kind": "List"}


def build_pod_list(profile: dict[str, Any], kubernetes: dict[str, Any]) -> dict[str, Any]:
    resources = _resource_map(kubernetes)
    items = []
    for index, service in enumerate(deployment.SERVICES):
        kind = "StatefulSet" if service == "generationcoordinator" else "Deployment"
        controller = resources[(kind, f"{profile['deployment_id']}-{service}")]
        template = controller["spec"]["template"]
        items.append({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {
                "annotations": template["metadata"]["annotations"],
                "labels": template["metadata"]["labels"],
                "name": f"{profile['deployment_id']}-q{index}",
                "namespace": profile["namespace"],
            },
            "spec": template["spec"],
        })
    return {"apiVersion": "v1", "items": items, "kind": "List"}


def build_negative_documents(
    profile: dict[str, Any], kubernetes: dict[str, Any],
    prerequisite_list: dict[str, Any], pod_list: dict[str, Any], qualification_id: str,
) -> list[tuple[str, str, dict[str, Any]]]:
    resources = _resource_map(kubernetes)
    records: list[tuple[str, str, dict[str, Any]]] = []
    policy = lambda category: f"{profile['deployment_id']}-{category}.{admission.POLICY_DOMAIN}"

    pod = copy.deepcopy(pod_list["items"][0])
    pod["spec"]["containers"][0]["image"] = "registry.invalid/qualification:latest"
    records.append(("pods", policy("pods"), pod))

    deploy = copy.deepcopy(resources[("Deployment", f"{profile['deployment_id']}-gateway")])
    deploy["spec"]["replicas"] = 2
    records.append(("deployments", policy("deployments"), deploy))

    stateful = copy.deepcopy(resources[("StatefulSet", f"{profile['deployment_id']}-generationcoordinator")])
    stateful["spec"]["replicas"] = 2
    records.append(("statefulsets", policy("statefulsets"), stateful))

    service = copy.deepcopy(resources[("Service", f"{profile['deployment_id']}-gateway")])
    service["spec"]["type"] = "LoadBalancer"
    records.append(("services", policy("services"), service))

    account = copy.deepcopy(resources[("ServiceAccount", f"{profile['deployment_id']}-gateway")])
    account["automountServiceAccountToken"] = True
    records.append(("serviceaccounts", policy("serviceaccounts"), account))

    network = copy.deepcopy(resources[("NetworkPolicy", f"{profile['deployment_id']}-gateway-egress")])
    network["spec"]["egress"][0]["to"] = [{"ipBlock": {"cidr": "0.0.0.0/0"}}]
    records.append(("networkpolicies", policy("networkpolicies"), network))

    config = copy.deepcopy(next(item for item in prerequisite_list["items"] if item["kind"] == "ConfigMap"))
    config["immutable"] = False
    records.append(("configmaps", policy("configmaps"), config))

    secret = copy.deepcopy(next(item for item in prerequisite_list["items"] if item["kind"] == "Secret"))
    secret["immutable"] = False
    records.append(("secrets", policy("secrets"), secret))

    pvc = copy.deepcopy(next(item for item in prerequisite_list["items"] if item["kind"] == "PersistentVolumeClaim"))
    pvc["metadata"]["name"] = "qualification-extra-" + oci._sha256(qualification_id.encode("utf-8"))[:12]
    records.append(("persistentvolumeclaims", policy("persistentvolumeclaims"), pvc))

    if tuple(category for category, _, _ in records) != NEGATIVE_CATEGORIES[:-1]:
        raise QualificationError("negative qualification matrix is incomplete")
    return records


def _policy_status(client: Any, names: list[str], timeout_seconds: int) -> list[dict[str, Any]]:
    if not 5 <= timeout_seconds <= 300:
        raise QualificationError("type-check timeout must be 5 through 300 seconds")
    deadline = time.monotonic() + timeout_seconds
    while True:
        records: list[dict[str, Any]] = []
        incomplete = False
        for name in names:
            item = client.get("validatingadmissionpolicy", name)
            metadata = item.get("metadata", {})
            status = item.get("status", {})
            if "typeChecking" not in status or status.get("observedGeneration") != metadata.get("generation"):
                incomplete = True
                break
            warnings = status["typeChecking"].get("expressionWarnings", [])
            if not isinstance(warnings, list):
                raise QualificationError("policy type-check warning status is malformed")
            if warnings:
                raise QualificationError(f"policy {name} has CEL type-check warnings")
            generation = metadata.get("generation")
            if type(generation) is not int or generation < 1:
                raise QualificationError(f"policy {name} generation is invalid")
            records.append({
                "name": name,
                "uid": _uid(metadata.get("uid"), f"policy {name} UID"),
                "generation": generation,
                "observed_generation": status.get("observedGeneration"),
                "expression_warning_count": 0,
            })
        if not incomplete and len(records) == len(names):
            return records
        if time.monotonic() >= deadline:
            raise QualificationError("policy CEL type-check status did not converge")
        time.sleep(1)


def _cleanup(
    client: Any, policy_names: list[str], binding_names: list[str],
    namespace: str, qualification_id: str,
) -> None:
    errors = []
    def delete_owned(resource: str, name: str) -> None:
        try:
            if not client.exists(resource, name):
                return
            item = client.get(resource, name)
            annotations = item.get("metadata", {}).get("annotations", {})
            if annotations.get(QUALIFICATION_ANNOTATION) != qualification_id:
                errors.append(f"refused cleanup of unowned {resource}/{name}")
                return
            client.delete(resource, name)
        except BaseException as error:
            errors.append(str(error))

    for name in reversed(binding_names):
        delete_owned("validatingadmissionpolicybinding", name)
    for name in reversed(policy_names):
        delete_owned("validatingadmissionpolicy", name)
    delete_owned("namespace", namespace)
    for resource, names in (
        ("validatingadmissionpolicybinding", binding_names),
        ("validatingadmissionpolicy", policy_names),
        ("namespace", [namespace]),
    ):
        for name in names:
            try:
                if client.exists(resource, name):
                    errors.append(f"{resource}/{name} remains or raced after cleanup")
            except BaseException as error:
                errors.append(str(error))
    if errors:
        raise QualificationError("qualification cleanup failed: " + "; ".join(errors[:3]))


def _write_bundle(output_path: Path, evidence: dict[str, Any], receipt: dict[str, Any]) -> None:
    if output_path.exists() or output_path.is_symlink():
        raise QualificationError("qualification output already exists")
    if not output_path.parent.is_dir():
        raise QualificationError("qualification output parent does not exist")
    evidence_data = oci._json_bytes(evidence)
    receipt_data = oci._json_bytes(receipt)
    created = False
    try:
        output_path.mkdir(mode=0o700)
        created = True
        oci._write_new(output_path / "evidence.json", evidence_data)
        oci._write_new(output_path / "qualification-receipt.json", receipt_data)
        oci._write_new(output_path / "READY", (oci._sha256(receipt_data) + "\n").encode("ascii"))
        oci._fsync_directory(output_path)
        oci._lock_tree(output_path)
    except BaseException:
        if created:
            oci._unlock_tree(output_path)
            shutil.rmtree(output_path)
        raise


def qualify(
    *, client: Any, admission_bundle: Path, deployment_bundle: Path,
    oci_bundle: Path, oci_trusted_public_key: Path, oci_signing_key_id: str,
    expected_oci_release_id: str, deployment_trusted_public_key: Path,
    deployment_signing_key_id: str, expected_deployment_id: str,
    admission_trusted_public_key: Path, admission_signing_key_id: str,
    qualification_id: str, expected_cluster_server: str,
    expected_kube_system_uid: str, expected_kubectl_sha256: str,
    expected_tool_sha256: str,
    signing_private_key_path: Path, signing_key_id: str, output_path: Path,
    typecheck_timeout_seconds: int = 60,
) -> dict[str, Any]:
    qualification_id = _identifier(qualification_id, "qualification ID")
    signing_key_id = _identifier(signing_key_id, "qualification signing key ID")
    expected_cluster_server = _cluster_server(expected_cluster_server)
    expected_kube_system_uid = _uid(expected_kube_system_uid, "expected kube-system UID")
    expected_kubectl_sha256 = _sha256(expected_kubectl_sha256, "expected kubectl SHA-256")
    expected_tool_sha256 = _sha256(expected_tool_sha256, "expected qualification tool SHA-256")
    actual_tool_sha256 = oci._sha256(oci._read_regular(Path(__file__).resolve(), MAX_TOOL_BYTES, "qualification tool"))
    if actual_tool_sha256 != expected_tool_sha256:
        raise QualificationError("qualification tool digest does not match external trust policy")
    if output_path.exists() or output_path.is_symlink():
        raise QualificationError("qualification output already exists")
    if not output_path.parent.is_dir():
        raise QualificationError("qualification output parent does not exist")
    private_key = oci._load_private_key(signing_private_key_path)
    admission_receipt = admission.validate_bundle(
        admission_bundle, deployment_bundle=deployment_bundle,
        oci_bundle=oci_bundle, oci_trusted_public_key=oci_trusted_public_key,
        expected_oci_signing_key_id=oci_signing_key_id,
        expected_oci_release_id=expected_oci_release_id,
        deployment_trusted_public_key=deployment_trusted_public_key,
        expected_deployment_signing_key_id=deployment_signing_key_id,
        expected_deployment_id=expected_deployment_id,
        trusted_public_key=admission_trusted_public_key,
        expected_signing_key_id=admission_signing_key_id,
    )
    admission_receipt_data = oci._read_regular(
        admission_bundle / "admission-receipt.json", oci.MAX_JSON_BYTES,
        "admission receipt",
    )
    admission_receipt_sha256 = oci._sha256(admission_receipt_data)
    admission_document = oci._strict_json(
        oci._read_regular(admission_bundle / "admission.json", oci.MAX_JSON_BYTES, "admission resources"),
        "admission resources",
    )
    profile, _ = deployment.load_profile(deployment_bundle / "profile.json")
    kubernetes = oci._strict_json(
        oci._read_regular(deployment_bundle / "kubernetes.json", oci.MAX_JSON_BYTES, "Kubernetes resources"),
        "Kubernetes resources",
    )
    prerequisites = oci._strict_json(
        oci._read_regular(deployment_bundle / "prerequisites.json", oci.MAX_JSON_BYTES, "deployment prerequisites"),
        "deployment prerequisites",
    )
    policy_names = [
        item["metadata"]["name"] for item in admission_document["items"]
        if item["kind"] == "ValidatingAdmissionPolicy"
    ]
    binding_names = [
        item["metadata"]["name"] for item in admission_document["items"]
        if item["kind"] == "ValidatingAdmissionPolicyBinding"
    ]
    if len(policy_names) != 10 or len(binding_names) != 10:
        raise QualificationError("admission policy inventory is incomplete")
    cluster = client.cluster_identity()
    if cluster.get("server") != expected_cluster_server or cluster.get("kube_system_uid") != expected_kube_system_uid or cluster.get("kubectl_sha256") != expected_kubectl_sha256:
        raise QualificationError("live cluster identity or kubectl digest does not match external trust policy")
    for resource, names in (
        ("validatingadmissionpolicy", policy_names),
        ("validatingadmissionpolicybinding", binding_names),
        ("namespace", [profile["namespace"]]),
    ):
        for name in names:
            if client.exists(resource, name):
                raise QualificationError(f"qualification refuses pre-existing {resource}/{name}")

    namespace_document = build_namespace(profile, prerequisites)
    prerequisite_list = build_prerequisite_list(profile, prerequisites, qualification_id)
    pod_list = build_pod_list(profile, kubernetes)
    negative_documents = build_negative_documents(
        profile, kubernetes, prerequisite_list, pod_list, qualification_id,
    )
    started_at = _now()
    client.apply(admission_document, dry_run=True, expected_count=20)
    owned_admission_items = [
        _owned_document(item, qualification_id) for item in admission_document["items"]
    ]
    owned_namespace = _owned_document(namespace_document, qualification_id)
    mutated = False
    run_data: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        mutated = True
        for item in owned_admission_items:
            client.create(item)
        type_checking = _policy_status(client, policy_names, typecheck_timeout_seconds)
        binding_status = []
        for name in binding_names:
            item = client.get("validatingadmissionpolicybinding", name)
            binding_status.append({
                "name": name,
                "uid": _uid(item.get("metadata", {}).get("uid"), f"binding {name} UID"),
            })
        client.create(owned_namespace)
        namespace_live = client.get("namespace", profile["namespace"])
        namespace_uid = _uid(namespace_live.get("metadata", {}).get("uid"), "qualification namespace UID")
        positive = [
            {"mode": "server_dry_run", "name": "signed-admission-graph", "passed": True, "resource_count": 20},
            {"mode": "live_create", "name": "admission-policy-install", "passed": True, "resource_count": 20},
            {"mode": "live_create", "name": "protected-namespace-create", "passed": True, "resource_count": 1},
        ]
        client.apply(kubernetes, dry_run=True, expected_count=44)
        positive.append({"mode": "server_dry_run", "name": "signed-workload-graph", "passed": True, "resource_count": 44})
        client.apply(pod_list, dry_run=True, expected_count=7)
        positive.append({"mode": "server_dry_run", "name": "controller-pod-graph", "passed": True, "resource_count": 7})
        client.apply(prerequisite_list, dry_run=True, expected_count=25)
        positive.append({"mode": "server_dry_run", "name": "external-prerequisite-graph", "passed": True, "resource_count": 25})

        pvc = copy.deepcopy(next(item for item in prerequisite_list["items"] if item["kind"] == "PersistentVolumeClaim" and item["metadata"]["name"] == profile["storage_claims"]["generation_state"]))
        client.create(_owned_document(pvc, qualification_id))
        pvc_live = client.get("persistentvolumeclaim", pvc["metadata"]["name"])
        if pvc_live.get("status", {}).get("phase") not in {None, "Pending"} or pvc_live.get("spec", {}).get("volumeName"):
            raise QualificationError("qualification PVC unexpectedly bound before the one-time binding probe")
        probe_volume = "qualification-unbound-" + oci._sha256(qualification_id.encode("utf-8"))[:12]
        client.patch("persistentvolumeclaim", pvc["metadata"]["name"], {"spec": {"volumeName": probe_volume}}, dry_run=True)
        positive.append({"mode": "live_create_and_server_dry_run", "name": "pvc-one-time-controller-binding", "passed": True, "resource_count": 1})

        negative = []
        for category, policy_name, document in negative_documents:
            client.expect_denied(document, policy_name=policy_name)
            negative.append({
                "category": category, "denial_observed": True,
                "policy_name": policy_name,
                "request_sha256": oci._sha256(oci._json_bytes(document)),
                "server_dry_run": True,
            })
        namespace_policy = f"{profile['deployment_id']}-namespace.{admission.POLICY_DOMAIN}"
        namespace_patch = {"metadata": {"labels": {"xiaozhi-agent/deployment-id": None}}}
        client.patch("namespace", profile["namespace"], namespace_patch, dry_run=True, expected_policy=namespace_policy)
        negative.append({
            "category": "namespace", "denial_observed": True,
            "policy_name": namespace_policy,
            "request_sha256": oci._sha256(oci._json_bytes(namespace_patch)),
            "server_dry_run": True,
        })
        if tuple(item["category"] for item in negative) != NEGATIVE_CATEGORIES:
            raise QualificationError("live negative admission matrix is incomplete")
        run_data = {
            "binding_status": binding_status,
            "namespace_uid": namespace_uid,
            "negative_tests": negative,
            "policy_type_checking": type_checking,
            "positive_tests": positive,
        }
    except BaseException as error:
        primary_error = error
    cleanup_error: BaseException | None = None
    if mutated:
        try:
            _cleanup(client, policy_names, binding_names, profile["namespace"], qualification_id)
        except BaseException as error:
            cleanup_error = error
    if primary_error is not None:
        if cleanup_error is not None:
            raise QualificationError(f"qualification failed and cleanup also failed: {cleanup_error}") from primary_error
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error
    if run_data is None:
        raise QualificationError("qualification produced no live evidence")

    finished_at = _now()
    evidence = {
        "schema": SCHEMA_VERSION,
        "qualification_id": qualification_id,
        "result": RESULT,
        "cluster": cluster,
        "deployment": {
            "admission_receipt_sha256": admission_receipt_sha256,
            "admission_signing_key_id": admission_receipt["signing_key_id"],
            "binding_names": binding_names,
            "deployment_id": profile["deployment_id"],
            "namespace": profile["namespace"],
            "policy_names": policy_names,
        },
        **run_data,
        "cleanup": {"bindings_absent": True, "namespace_absent": True, "policies_absent": True},
        "qualification_tool_sha256": actual_tool_sha256,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    validate_evidence(
        evidence,
        admission_document=admission_document,
        admission_receipt_sha256=admission_receipt_sha256,
        admission_signing_key_id=admission_receipt["signing_key_id"],
        expected_qualification_id=qualification_id,
        expected_deployment_id=profile["deployment_id"],
        expected_namespace=profile["namespace"],
        expected_cluster_server=expected_cluster_server,
        expected_kube_system_uid=expected_kube_system_uid,
        expected_kubectl_sha256=expected_kubectl_sha256,
        expected_tool_sha256=expected_tool_sha256,
    )
    evidence_data = oci._json_bytes(evidence)
    receipt: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "qualification_id": qualification_id,
        "result": RESULT,
        "deployment_id": profile["deployment_id"],
        "namespace": profile["namespace"],
        "admission_receipt_sha256": admission_receipt_sha256,
        "cluster_server": cluster["server"],
        "kube_system_uid": cluster["kube_system_uid"],
        "evidence_sha256": oci._sha256(evidence_data),
        "qualification_tool_sha256": actual_tool_sha256,
        "started_at": started_at,
        "finished_at": finished_at,
        "signing_key_id": signing_key_id,
        "signature_algorithm": "Ed25519",
    }
    receipt["signature_b64url"] = oci._b64url(private_key.sign(_signature_payload(receipt)))
    _write_bundle(output_path, evidence, receipt)
    return receipt


def recover_cleanup(
    *, client: Any, admission_bundle: Path, deployment_bundle: Path,
    oci_bundle: Path, oci_trusted_public_key: Path, oci_signing_key_id: str,
    expected_oci_release_id: str, deployment_trusted_public_key: Path,
    deployment_signing_key_id: str, expected_deployment_id: str,
    admission_trusted_public_key: Path, admission_signing_key_id: str,
    qualification_id: str, expected_cluster_server: str,
    expected_kube_system_uid: str, expected_kubectl_sha256: str,
    expected_tool_sha256: str,
) -> dict[str, Any]:
    """Remove only interrupted M51 objects owned by the exact qualification ID."""
    qualification_id = _identifier(qualification_id, "qualification ID")
    expected_cluster_server = _cluster_server(expected_cluster_server)
    expected_kube_system_uid = _uid(expected_kube_system_uid, "expected kube-system UID")
    expected_kubectl_sha256 = _sha256(expected_kubectl_sha256, "expected kubectl SHA-256")
    expected_tool_sha256 = _sha256(expected_tool_sha256, "expected qualification tool SHA-256")
    actual_tool_sha256 = oci._sha256(oci._read_regular(Path(__file__).resolve(), MAX_TOOL_BYTES, "qualification tool"))
    if actual_tool_sha256 != expected_tool_sha256:
        raise QualificationError("qualification tool digest does not match external trust policy")
    admission.validate_bundle(
        admission_bundle, deployment_bundle=deployment_bundle,
        oci_bundle=oci_bundle, oci_trusted_public_key=oci_trusted_public_key,
        expected_oci_signing_key_id=oci_signing_key_id,
        expected_oci_release_id=expected_oci_release_id,
        deployment_trusted_public_key=deployment_trusted_public_key,
        expected_deployment_signing_key_id=deployment_signing_key_id,
        expected_deployment_id=expected_deployment_id,
        trusted_public_key=admission_trusted_public_key,
        expected_signing_key_id=admission_signing_key_id,
    )
    admission_document = oci._strict_json(
        oci._read_regular(admission_bundle / "admission.json", oci.MAX_JSON_BYTES, "admission resources"),
        "admission resources",
    )
    profile, _ = deployment.load_profile(deployment_bundle / "profile.json")
    policy_names = [item["metadata"]["name"] for item in admission_document["items"] if item["kind"] == "ValidatingAdmissionPolicy"]
    binding_names = [item["metadata"]["name"] for item in admission_document["items"] if item["kind"] == "ValidatingAdmissionPolicyBinding"]
    cluster = client.cluster_identity()
    if cluster.get("server") != expected_cluster_server or cluster.get("kube_system_uid") != expected_kube_system_uid or cluster.get("kubectl_sha256") != expected_kubectl_sha256:
        raise QualificationError("cleanup cluster identity or kubectl digest does not match external trust policy")
    _cleanup(client, policy_names, binding_names, profile["namespace"], qualification_id)
    return {
        "binding_count": len(binding_names),
        "deployment_id": profile["deployment_id"],
        "namespace": profile["namespace"],
        "policy_count": len(policy_names),
        "qualification_id": qualification_id,
        "result": "OWNED_SCOPE_ABSENT",
    }


def validate_evidence(
    evidence: object, *, admission_document: dict[str, Any],
    admission_receipt_sha256: str, admission_signing_key_id: str,
    expected_qualification_id: str, expected_deployment_id: str,
    expected_namespace: str,
    expected_cluster_server: str, expected_kube_system_uid: str,
    expected_kubectl_sha256: str, expected_tool_sha256: str,
) -> dict[str, Any]:
    fields = {
        "schema", "qualification_id", "result", "cluster", "deployment",
        "binding_status", "namespace_uid", "negative_tests",
        "policy_type_checking", "positive_tests", "cleanup", "started_at",
        "finished_at", "qualification_tool_sha256",
    }
    if not isinstance(evidence, dict) or set(evidence) != fields or evidence.get("schema") != 1 or evidence.get("result") != RESULT:
        raise QualificationError("qualification evidence fields or result are invalid")
    if evidence.get("qualification_id") != expected_qualification_id:
        raise QualificationError("qualification evidence ID does not match trust policy")
    cluster = evidence.get("cluster")
    if not isinstance(cluster, dict) or set(cluster) != {"context", "server", "kube_system_uid", "client_git_version", "server_git_version", "server_platform", "kubectl_sha256"}:
        raise QualificationError("qualification cluster evidence is invalid")
    _identifier(cluster["context"], "evidence context")
    if _cluster_server(cluster["server"]) != expected_cluster_server or _uid(cluster["kube_system_uid"], "evidence kube-system UID") != expected_kube_system_uid or _sha256(cluster["kubectl_sha256"], "evidence kubectl SHA-256") != expected_kubectl_sha256:
        raise QualificationError("qualification cluster evidence does not match trust policy")
    _git_version(cluster["client_git_version"], "evidence kubectl version")
    _git_version(cluster["server_git_version"], "evidence server version")
    if not isinstance(cluster["server_platform"], str) or not re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", cluster["server_platform"]):
        raise QualificationError("qualification server platform is invalid")
    deployment_evidence = evidence.get("deployment")
    if not isinstance(deployment_evidence, dict) or set(deployment_evidence) != {"admission_receipt_sha256", "admission_signing_key_id", "binding_names", "deployment_id", "namespace", "policy_names"}:
        raise QualificationError("qualification deployment evidence is invalid")
    expected_policy_names = [item["metadata"]["name"] for item in admission_document["items"] if item["kind"] == "ValidatingAdmissionPolicy"]
    expected_binding_names = [item["metadata"]["name"] for item in admission_document["items"] if item["kind"] == "ValidatingAdmissionPolicyBinding"]
    if deployment_evidence != {
        "admission_receipt_sha256": admission_receipt_sha256,
        "admission_signing_key_id": admission_signing_key_id,
        "binding_names": expected_binding_names,
        "deployment_id": expected_deployment_id,
        "namespace": expected_namespace,
        "policy_names": expected_policy_names,
    }:
        raise QualificationError("qualification deployment evidence is not receipt-bound")
    if not isinstance(expected_namespace, str) or not deployment.DNS_LABEL.fullmatch(expected_namespace):
        raise QualificationError("qualification namespace is invalid")
    type_records = evidence.get("policy_type_checking")
    if not isinstance(type_records, list) or len(type_records) != 10 or [item.get("name") for item in type_records] != expected_policy_names:
        raise QualificationError("qualification type-check inventory is incomplete")
    for item in type_records:
        if set(item) != {"name", "uid", "generation", "observed_generation", "expression_warning_count"} or item["generation"] != item["observed_generation"] or type(item["generation"]) is not int or item["generation"] < 1 or item["expression_warning_count"] != 0:
            raise QualificationError("qualification policy type-check result is invalid")
        _uid(item["uid"], "policy evidence UID")
    binding_records = evidence.get("binding_status")
    if not isinstance(binding_records, list) or len(binding_records) != 10 or [item.get("name") for item in binding_records] != expected_binding_names:
        raise QualificationError("qualification binding inventory is incomplete")
    for item in binding_records:
        if set(item) != {"name", "uid"}:
            raise QualificationError("qualification binding evidence is invalid")
        _uid(item["uid"], "binding evidence UID")
    _uid(evidence.get("namespace_uid"), "qualification namespace UID")
    positive = evidence.get("positive_tests")
    expected_positive = [
        ("signed-admission-graph", "server_dry_run", 20),
        ("admission-policy-install", "live_create", 20),
        ("protected-namespace-create", "live_create", 1),
        ("signed-workload-graph", "server_dry_run", 44),
        ("controller-pod-graph", "server_dry_run", 7),
        ("external-prerequisite-graph", "server_dry_run", 25),
        ("pvc-one-time-controller-binding", "live_create_and_server_dry_run", 1),
    ]
    if not isinstance(positive, list) or [(item.get("name"), item.get("mode"), item.get("resource_count")) for item in positive] != expected_positive or not all(item.get("passed") is True and set(item) == {"mode", "name", "passed", "resource_count"} for item in positive):
        raise QualificationError("qualification positive matrix is incomplete")
    negative = evidence.get("negative_tests")
    if not isinstance(negative, list) or tuple(item.get("category") for item in negative) != NEGATIVE_CATEGORIES:
        raise QualificationError("qualification negative matrix is incomplete")
    for item, policy_name in zip(negative, expected_policy_names):
        if set(item) != {"category", "denial_observed", "policy_name", "request_sha256", "server_dry_run"} or item["denial_observed"] is not True or item["server_dry_run"] is not True or item["policy_name"] != policy_name:
            raise QualificationError("qualification negative denial evidence is invalid")
        _sha256(item["request_sha256"], "negative request SHA-256")
    if evidence.get("cleanup") != {"bindings_absent": True, "namespace_absent": True, "policies_absent": True}:
        raise QualificationError("qualification cleanup is incomplete")
    if _sha256(evidence.get("qualification_tool_sha256"), "evidence qualification tool SHA-256") != expected_tool_sha256:
        raise QualificationError("qualification tool evidence does not match trust policy")
    for label in ("started_at", "finished_at"):
        if not isinstance(evidence.get(label), str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", evidence[label]):
            raise QualificationError(f"qualification {label} is invalid")
    started = datetime.fromisoformat(evidence["started_at"][:-1] + "+00:00")
    finished = datetime.fromisoformat(evidence["finished_at"][:-1] + "+00:00")
    if finished < started or (finished - started).total_seconds() > 7200:
        raise QualificationError("qualification time window is invalid")
    return evidence


def validate_bundle(
    root: Path, *, admission_bundle: Path, deployment_bundle: Path,
    oci_bundle: Path, oci_trusted_public_key: Path,
    expected_oci_signing_key_id: str, expected_oci_release_id: str,
    deployment_trusted_public_key: Path,
    expected_deployment_signing_key_id: str, expected_deployment_id: str,
    admission_trusted_public_key: Path,
    expected_admission_signing_key_id: str, trusted_public_key: Path,
    expected_signing_key_id: str, expected_qualification_id: str,
    expected_cluster_server: str, expected_kube_system_uid: str,
    expected_kubectl_sha256: str, expected_tool_sha256: str,
) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise QualificationError("qualification bundle must be a non-symlink directory")
    expected_files = {"READY", "evidence.json", "qualification-receipt.json"}
    files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()) or path.stat().st_mode & 0o222:
            raise QualificationError("qualification bundle contains a writable or non-regular object")
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
    if root.stat().st_mode & 0o222 or files != expected_files:
        raise QualificationError("qualification bundle layout or permissions are invalid")
    receipt_data = oci._read_regular(root / "qualification-receipt.json", oci.MAX_JSON_BYTES, "qualification receipt")
    receipt = oci._strict_json(receipt_data, "qualification receipt")
    fields = {
        "schema", "qualification_id", "result", "deployment_id", "namespace",
        "admission_receipt_sha256", "cluster_server", "kube_system_uid",
        "evidence_sha256", "started_at", "finished_at", "signing_key_id",
        "signature_algorithm", "signature_b64url", "qualification_tool_sha256",
    }
    if not isinstance(receipt, dict) or set(receipt) != fields or oci._json_bytes(receipt) != receipt_data or receipt.get("schema") != 1 or receipt.get("result") != RESULT or receipt.get("signature_algorithm") != "Ed25519":
        raise QualificationError("qualification receipt fields, schema or result are invalid")
    expected_cluster_server = _cluster_server(expected_cluster_server)
    expected_kube_system_uid = _uid(expected_kube_system_uid, "expected kube-system UID")
    expected_kubectl_sha256 = _sha256(expected_kubectl_sha256, "expected kubectl SHA-256")
    expected_tool_sha256 = _sha256(expected_tool_sha256, "expected qualification tool SHA-256")
    if receipt.get("qualification_id") != expected_qualification_id or receipt.get("deployment_id") != expected_deployment_id or receipt.get("signing_key_id") != expected_signing_key_id or receipt.get("cluster_server") != expected_cluster_server or receipt.get("kube_system_uid") != expected_kube_system_uid or receipt.get("qualification_tool_sha256") != expected_tool_sha256:
        raise QualificationError("qualification receipt does not match external trust policy")
    try:
        oci._load_public_key(trusted_public_key).verify(
            oci._decode_b64url(receipt.get("signature_b64url"), 64, "qualification signature"),
            _signature_payload(receipt),
        )
    except InvalidSignature as error:
        raise QualificationError("qualification receipt signature is invalid") from error
    if oci._read_regular(root / "READY", 128, "qualification READY") != (oci._sha256(receipt_data) + "\n").encode("ascii"):
        raise QualificationError("qualification READY marker is invalid")
    evidence_data = oci._read_regular(root / "evidence.json", oci.MAX_JSON_BYTES, "qualification evidence")
    if receipt.get("evidence_sha256") != oci._sha256(evidence_data):
        raise QualificationError("qualification evidence hash does not match receipt")
    admission_receipt = admission.validate_bundle(
        admission_bundle, deployment_bundle=deployment_bundle,
        oci_bundle=oci_bundle, oci_trusted_public_key=oci_trusted_public_key,
        expected_oci_signing_key_id=expected_oci_signing_key_id,
        expected_oci_release_id=expected_oci_release_id,
        deployment_trusted_public_key=deployment_trusted_public_key,
        expected_deployment_signing_key_id=expected_deployment_signing_key_id,
        expected_deployment_id=expected_deployment_id,
        trusted_public_key=admission_trusted_public_key,
        expected_signing_key_id=expected_admission_signing_key_id,
    )
    admission_receipt_data = oci._read_regular(admission_bundle / "admission-receipt.json", oci.MAX_JSON_BYTES, "admission receipt")
    admission_receipt_sha256 = oci._sha256(admission_receipt_data)
    if receipt.get("admission_receipt_sha256") != admission_receipt_sha256:
        raise QualificationError("qualification receipt is not bound to the trusted admission receipt")
    admission_document = oci._strict_json(
        oci._read_regular(admission_bundle / "admission.json", oci.MAX_JSON_BYTES, "admission resources"),
        "admission resources",
    )
    evidence = validate_evidence(
        oci._strict_json(evidence_data, "qualification evidence"),
        admission_document=admission_document,
        admission_receipt_sha256=admission_receipt_sha256,
        admission_signing_key_id=admission_receipt["signing_key_id"],
        expected_qualification_id=expected_qualification_id,
        expected_deployment_id=expected_deployment_id,
        expected_namespace=admission_receipt["namespace"],
        expected_cluster_server=expected_cluster_server,
        expected_kube_system_uid=expected_kube_system_uid,
        expected_kubectl_sha256=expected_kubectl_sha256,
        expected_tool_sha256=expected_tool_sha256,
    )
    if receipt.get("namespace") != evidence["deployment"]["namespace"] or receipt.get("started_at") != evidence["started_at"] or receipt.get("finished_at") != evidence["finished_at"]:
        raise QualificationError("qualification receipt and evidence disagree")
    return receipt
