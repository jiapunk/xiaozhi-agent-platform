#!/usr/bin/env python3
"""Signed deterministic Kubernetes admission policy bundle for an M49 deployment."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

import kubernetes_deployment as deployment
import oci_release as oci


SCHEMA_VERSION = 1
SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-KUBERNETES-ADMISSION-V1\x00"
POLICY_DOMAIN = "xiaozhi-agent.io"
CATEGORIES = (
    "pods", "deployments", "statefulsets", "services", "serviceaccounts",
    "networkpolicies", "configmaps", "secrets", "persistentvolumeclaims",
    "namespace",
)


class AdmissionError(ValueError):
    pass


def _q(value: str) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _cel_list(values: list[str] | tuple[str, ...]) -> str:
    return "[" + ",".join(_q(value) for value in values) + "]"


def _signature_payload(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("signature_b64url", None)
    return SIGNATURE_DOMAIN + oci._compact_bytes(unsigned)


def _resource_map(kubernetes: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (item["kind"], item["metadata"]["name"]): item
        for item in kubernetes["items"]
    }


def _fixed_map_expression(path: str, values: dict[str, str]) -> str:
    entries = ",".join(f"{_q(key)}:{_q(value)}" for key, value in sorted(values.items()))
    return f"{path} == {{{entries}}}"


def _pod_service_branch(
    profile: dict[str, Any], service: str, template: dict[str, Any],
    pod_path: str, labels_path: str,
) -> str:
    spec = template["spec"]
    container = spec["containers"][0]
    checks = [
        f"{labels_path}[{_q('app.kubernetes.io/component')}] == {_q(service)}",
        f"{pod_path}.serviceAccountName == {_q(spec['serviceAccountName'])}",
        f"{pod_path}.terminationGracePeriodSeconds == {spec['terminationGracePeriodSeconds']}",
        f"{pod_path}.containers[0].name == {_q(service)}",
        f"{pod_path}.containers[0].image == {_q(container['image'])}",
        f"{pod_path}.containers[0].imagePullPolicy == {_q(container['imagePullPolicy'])}",
        f"size({pod_path}.containers[0].env) == {len(container['env'])}",
        f"size({pod_path}.containers[0].envFrom) == 2",
        f"{pod_path}.containers[0].envFrom.exists(e, has(e.configMapRef) && e.configMapRef.name == {_q(profile['config_maps'][service])} && e.configMapRef.optional == false)",
        f"{pod_path}.containers[0].envFrom.exists(e, has(e.secretRef) && e.secretRef.name == {_q(profile['secret_env'][service])} && e.secretRef.optional == false)",
        f"size({pod_path}.containers[0].volumeMounts) == {len(container['volumeMounts'])}",
        f"size({pod_path}.volumes) == {len(spec['volumes'])}",
        f"{pod_path}.imagePullSecrets == [{{'name': {_q(profile['image_pull_secret'])}}}]",
    ]
    for entry in container["env"]:
        if "value" in entry:
            checks.append(
                f"{pod_path}.containers[0].env.exists(e, e.name == {_q(entry['name'])} && "
                f"has(e.value) && e.value == {_q(entry['value'])} && !has(e.valueFrom))"
            )
        elif entry.get("valueFrom") == {
            "fieldRef": {"fieldPath": "metadata.name"}
        }:
            checks.append(
                f"{pod_path}.containers[0].env.exists(e, e.name == {_q(entry['name'])} && "
                "!has(e.value) && has(e.valueFrom) && has(e.valueFrom.fieldRef) && "
                "e.valueFrom.fieldRef.fieldPath == 'metadata.name' && "
                "(!has(e.valueFrom.fieldRef.apiVersion) || e.valueFrom.fieldRef.apiVersion == 'v1') && "
                "!has(e.valueFrom.resourceFieldRef) && !has(e.valueFrom.configMapKeyRef) && "
                "!has(e.valueFrom.secretKeyRef))"
            )
        else:
            raise AdmissionError("deployment contains an unsupported environment source")
    for mount in container["volumeMounts"]:
        read_only = "true" if mount["readOnly"] else "false"
        checks.append(
            f"{pod_path}.containers[0].volumeMounts.exists(m, m.name == {_q(mount['name'])} && "
            f"m.mountPath == {_q(mount['mountPath'])} && m.readOnly == {read_only} && !has(m.subPath))"
        )
    for volume in spec["volumes"]:
        if "secret" in volume:
            checks.append(
                f"{pod_path}.volumes.exists(v, v.name == {_q(volume['name'])} && has(v.secret) && "
                f"v.secret.secretName == {_q(volume['secret']['secretName'])} && v.secret.optional == false)"
            )
        else:
            claim = volume["persistentVolumeClaim"]
            read_only = "true" if claim["readOnly"] else "false"
            checks.append(
                f"{pod_path}.volumes.exists(v, v.name == {_q(volume['name'])} && "
                f"has(v.persistentVolumeClaim) && v.persistentVolumeClaim.claimName == {_q(claim['claimName'])} && "
                f"v.persistentVolumeClaim.readOnly == {read_only})"
            )
    resources = container["resources"]
    checks.extend([
        _fixed_map_expression(f"{pod_path}.containers[0].resources.requests", resources["requests"]),
        _fixed_map_expression(f"{pod_path}.containers[0].resources.limits", resources["limits"]),
    ])
    return "(" + " && ".join(checks) + ")"


def _pod_hardening_expression(
    profile: dict[str, Any], templates: dict[str, dict[str, Any]],
    pod_path: str, labels_path: str,
) -> str:
    branches = [
        _pod_service_branch(profile, service, templates[service], pod_path, labels_path)
        for service in deployment.SERVICES
    ]
    return " && ".join([
        f"has({labels_path})",
        f"{labels_path}[{_q('app.kubernetes.io/instance')}] == {_q(profile['deployment_id'])}",
        f"{labels_path}[{_q('app.kubernetes.io/part-of')}] == {_q('xiaozhi-agent-platform')}",
        f"size({pod_path}.containers) == 1",
        f"(!has({pod_path}.initContainers) || size({pod_path}.initContainers) == 0)",
        f"(!has({pod_path}.ephemeralContainers) || size({pod_path}.ephemeralContainers) == 0)",
        f"{pod_path}.automountServiceAccountToken == false",
        f"{pod_path}.hostNetwork == false && {pod_path}.hostPID == false && {pod_path}.hostIPC == false",
        f"{pod_path}.enableServiceLinks == false",
        f"{pod_path}.dnsPolicy == 'ClusterFirst' && {pod_path}.restartPolicy == 'Always'",
        f"{pod_path}.nodeSelector == {{'kubernetes.io/os':'linux'}}",
        f"{pod_path}.securityContext.runAsNonRoot == true",
        f"{pod_path}.securityContext.runAsUser == 65532 && {pod_path}.securityContext.runAsGroup == 65532",
        f"{pod_path}.securityContext.fsGroup == 65532",
        f"{pod_path}.securityContext.seccompProfile.type == 'RuntimeDefault'",
        f"{pod_path}.containers[0].securityContext.allowPrivilegeEscalation == false",
        f"{pod_path}.containers[0].securityContext.privileged == false",
        f"{pod_path}.containers[0].securityContext.readOnlyRootFilesystem == true",
        f"{pod_path}.containers[0].securityContext.runAsNonRoot == true",
        f"{pod_path}.containers[0].securityContext.runAsUser == 65532 && {pod_path}.containers[0].securityContext.runAsGroup == 65532",
        f"{pod_path}.containers[0].securityContext.capabilities.drop == ['ALL']",
        f"(!has({pod_path}.containers[0].command) || size({pod_path}.containers[0].command) == 0)",
        f"(!has({pod_path}.containers[0].args) || size({pod_path}.containers[0].args) == 0)",
        "(" + " || ".join(branches) + ")",
    ])


def _validation(expression: str, message: str) -> dict[str, str]:
    return {"expression": expression, "message": message, "reason": "Forbidden"}


def _policy(
    profile: dict[str, Any], deployment_receipt_sha256: str, category: str,
    api_groups: list[str], resources: list[str], scope: str,
    validations: list[dict[str, str]], *, exact_namespace: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    name = f"{profile['deployment_id']}-{category}.{POLICY_DOMAIN}"
    annotations = {
        "xiaozhi-agent/deployment-id": profile["deployment_id"],
        "xiaozhi-agent/deployment-receipt-sha256": deployment_receipt_sha256,
    }
    match_condition = (
        f"request.namespace == {_q(profile['namespace'])}"
        if exact_namespace else f"request.name == {_q(profile['namespace'])}"
    )
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"annotations": annotations, "name": name},
        "spec": {
            "auditAnnotations": [{
                "key": "denied-category",
                "valueExpression": _q(category),
            }],
            "failurePolicy": "Fail",
            "matchConditions": [{"expression": match_condition, "name": "exact-deployment-scope"}],
            "matchConstraints": {"resourceRules": [{
                "apiGroups": api_groups,
                "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE", "DELETE"],
                "resources": resources,
                "scope": scope,
            }]},
            "validations": validations,
        },
    }
    match_resources: dict[str, Any] = {}
    if exact_namespace:
        match_resources["namespaceSelector"] = {"matchLabels": {
            "xiaozhi-agent/deployment-id": profile["deployment_id"],
        }}
    binding_spec: dict[str, Any] = {
        "policyName": name,
        "validationActions": ["Deny", "Audit"],
    }
    if match_resources:
        binding_spec["matchResources"] = match_resources
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"annotations": annotations, "name": f"{profile['deployment_id']}-{category}-binding.{POLICY_DOMAIN}"},
        "spec": binding_spec,
    }
    return policy, binding


def build_admission_list(
    profile: dict[str, Any], kubernetes: dict[str, Any], prerequisites: dict[str, Any],
    deployment_receipt_sha256: str,
) -> dict[str, Any]:
    resources = _resource_map(kubernetes)
    templates = {
        service: resources[("StatefulSet" if service == "generationcoordinator" else "Deployment",
                            f"{profile['deployment_id']}-{service}")]["spec"]["template"]
        for service in deployment.SERVICES
    }
    deployment_names = [f"{profile['deployment_id']}-{service}" for service in deployment.SERVICES if service != "generationcoordinator"]
    stateful_names = [f"{profile['deployment_id']}-generationcoordinator"]
    service_names = [f"{profile['deployment_id']}-{service}" for service in deployment.SERVICES]
    network_names = sorted(
        item["metadata"]["name"] for item in kubernetes["items"]
        if item["kind"] == "NetworkPolicy"
    )
    config_prerequisites = [item for item in prerequisites["objects"] if item["kind"] == "ConfigMap"]
    secret_prerequisites = [item for item in prerequisites["objects"] if item["kind"] == "Secret"]
    pvc_prerequisites = [item for item in prerequisites["objects"] if item["kind"] == "PersistentVolumeClaim"]
    items: list[dict[str, Any]] = []

    def add(category: str, groups: list[str], api_resources: list[str], scope: str,
            validations: list[dict[str, str]], *, namespaced: bool = True) -> None:
        policy, binding = _policy(
            profile, deployment_receipt_sha256, category, groups, api_resources,
            scope, validations, exact_namespace=namespaced,
        )
        items.extend([policy, binding])

    add("pods", [""], ["pods"], "Namespaced", [
        _validation(
            "request.operation == 'DELETE' || (" + _pod_hardening_expression(
                profile, templates, "object.spec", "object.metadata.labels") + ")",
            "Pod must preserve the signed service identity and hardened runtime contract",
        ),
        _validation(
            "request.operation != 'UPDATE' || object.spec == oldObject.spec",
            "Pod spec is immutable; replace it through its signed workload controller",
        ),
    ])

    workload_common = [
        _validation("request.operation != 'DELETE'", "Signed workload controllers cannot be deleted"),
        _validation("request.operation != 'UPDATE' || object.spec == oldObject.spec", "Signed workload controller spec is immutable"),
    ]
    add("deployments", ["apps"], ["deployments"], "Namespaced", [
        _validation(f"request.name in {_cel_list(deployment_names)}", "Only the six signed Deployment names are allowed"),
        *workload_common,
        _validation(
            "request.operation != 'CREATE' || (object.spec.replicas == 1 && object.spec.strategy.type == 'Recreate' && "
            "object.spec.revisionHistoryLimit == 2 && object.spec.template.spec.containers[0].image.contains('@sha256:') && (" +
            _pod_hardening_expression(profile, templates, "object.spec.template.spec", "object.spec.template.metadata.labels") + "))",
            "Deployment creation must match the signed single-replica hardened contract",
        ),
    ])
    add("statefulsets", ["apps"], ["statefulsets"], "Namespaced", [
        _validation(f"request.name in {_cel_list(stateful_names)}", "Only the signed generation StatefulSet is allowed"),
        *workload_common,
        _validation(
            "request.operation != 'CREATE' || (object.spec.replicas == 1 && object.spec.updateStrategy.type == 'OnDelete' && "
            f"object.spec.serviceName == {_q(stateful_names[0])} && (" +
            _pod_hardening_expression(profile, templates, "object.spec.template.spec", "object.spec.template.metadata.labels") + "))",
            "StatefulSet creation must match the signed generation contract",
        ),
    ])

    service_branches = []
    for service in deployment.SERVICES:
        expected = resources[("Service", f"{profile['deployment_id']}-{service}")]["spec"]
        conditions = [
            f"request.name == {_q(profile['deployment_id'] + '-' + service)}",
            f"object.spec.type == {_q(expected['type'])}",
            f"size(object.spec.ports) == 1",
            f"object.spec.ports[0].port == {expected['ports'][0]['port']}",
            f"object.spec.ports[0].targetPort == {_q(expected['ports'][0]['targetPort'])}",
            _fixed_map_expression("object.spec.selector", expected["selector"]),
        ]
        if service == "generationcoordinator":
            conditions.append("object.spec.clusterIP == 'None'")
        service_branches.append("(" + " && ".join(conditions) + ")")
    add("services", [""], ["services"], "Namespaced", [
        _validation(f"request.name in {_cel_list(service_names)}", "Only the seven signed Services are allowed"),
        _validation("request.operation != 'DELETE'", "Signed Services cannot be deleted"),
        _validation("request.operation != 'UPDATE' || object.spec == oldObject.spec", "Signed Service spec is immutable"),
        _validation(
            "request.operation != 'CREATE' || ((!has(object.spec.externalIPs) || size(object.spec.externalIPs) == 0) && "
            "!has(object.spec.externalName) && !has(object.spec.loadBalancerClass) && (" + " || ".join(service_branches) + "))",
            "Service creation must preserve signed ClusterIP routing",
        ),
    ])

    add("serviceaccounts", [""], ["serviceaccounts"], "Namespaced", [
        _validation(f"request.name in {_cel_list(service_names)}", "Only the seven isolated ServiceAccounts are allowed"),
        _validation("request.operation != 'DELETE'", "Signed ServiceAccounts cannot be deleted"),
        _validation("request.operation != 'UPDATE' || object.automountServiceAccountToken == oldObject.automountServiceAccountToken", "ServiceAccount token policy is immutable"),
        _validation(
            "object.automountServiceAccountToken == false && (!has(object.secrets) || size(object.secrets) == 0) && "
            "(!has(object.imagePullSecrets) || size(object.imagePullSecrets) == 0)",
            "ServiceAccount must not mount API or registry credentials",
        ),
    ])

    add("networkpolicies", ["networking.k8s.io"], ["networkpolicies"], "Namespaced", [
        _validation(f"request.name in {_cel_list(network_names)}", "Only the signed NetworkPolicy inventory is allowed"),
        _validation("request.operation != 'DELETE'", "Signed NetworkPolicies cannot be deleted"),
        _validation("request.operation != 'UPDATE' || object.spec == oldObject.spec", "Signed NetworkPolicy spec is immutable"),
        _validation(
            "request.operation != 'CREATE' || ((!has(object.spec.ingress) || object.spec.ingress.all(r, !has(r.from) || "
            "r.from.all(p, !has(p.ipBlock) || (p.ipBlock.cidr != '0.0.0.0/0' && p.ipBlock.cidr != '::/0')))) && "
            "(!has(object.spec.egress) || object.spec.egress.all(r, !has(r.to) || r.to.all(p, !has(p.ipBlock) || "
            "(p.ipBlock.cidr != '0.0.0.0/0' && p.ipBlock.cidr != '::/0')))))",
            "NetworkPolicy must not introduce a default ingress or egress route",
        ),
    ])

    config_names = [item["name"] for item in config_prerequisites]
    config_branches = [
        "(request.name == " + _q(item["name"]) + " && size(object.data) == " +
        str(len(item["required_keys"])) + " && " +
        " && ".join(_q(key) + " in object.data" for key in item["required_keys"]) + ")"
        for item in config_prerequisites
    ]
    add("configmaps", [""], ["configmaps"], "Namespaced", [
        _validation(f"request.name in {_cel_list(config_names)}", "Only the seven signed ConfigMaps are allowed"),
        _validation("request.operation != 'DELETE'", "Signed ConfigMaps cannot be deleted"),
        _validation("request.operation != 'UPDATE' || object.data == oldObject.data", "Signed ConfigMap data is immutable"),
        _validation(
            "object.immutable == true && (!has(object.binaryData) || size(object.binaryData) == 0) && (" +
            " || ".join(config_branches) + ")",
            "ConfigMap must be immutable and contain its exact service key inventory",
        ),
    ])

    secret_names = [item["name"] for item in secret_prerequisites]
    secret_branches = [
        "(request.name == " + _q(item["name"]) + " && object.type == " + _q(item["type"]) +
        " && size(object.data) == " + str(len(item["required_keys"])) + " && " +
        " && ".join(_q(key) + " in object.data" for key in item["required_keys"]) + ")"
        for item in secret_prerequisites
    ]
    add("secrets", [""], ["secrets"], "Namespaced", [
        _validation(f"request.name in {_cel_list(secret_names)}", "Only the fifteen signed Secret objects are allowed"),
        _validation("request.operation != 'DELETE'", "Signed Secrets cannot be deleted"),
        _validation("request.operation != 'UPDATE' || object.data == oldObject.data", "Signed Secret data is immutable"),
        _validation(
            "object.immutable == true && (!has(object.stringData) || size(object.stringData) == 0) && (" +
            " || ".join(secret_branches) + ")",
            "Secret must be immutable and contain its exact type and key inventory",
        ),
    ])

    pvc_names = [item["name"] for item in pvc_prerequisites]
    add("persistentvolumeclaims", [""], ["persistentvolumeclaims"], "Namespaced", [
        _validation(f"request.name in {_cel_list(pvc_names)}", "Only the three signed PersistentVolumeClaims are allowed"),
        _validation("request.operation != 'DELETE'", "Signed PersistentVolumeClaims cannot be deleted"),
        _validation(
            "request.operation != 'UPDATE' || (object.spec.accessModes == oldObject.spec.accessModes && "
            "object.spec.resources == oldObject.spec.resources && "
            "object.spec.?storageClassName.orValue('') == oldObject.spec.?storageClassName.orValue('') && "
            "object.spec.?volumeMode.orValue('Filesystem') == oldObject.spec.?volumeMode.orValue('Filesystem') && "
            "((!has(object.spec.selector) && !has(oldObject.spec.selector)) || "
            "(has(object.spec.selector) && has(oldObject.spec.selector) && object.spec.selector == oldObject.spec.selector)) && "
            "((!has(object.spec.dataSource) && !has(oldObject.spec.dataSource)) || "
            "(has(object.spec.dataSource) && has(oldObject.spec.dataSource) && object.spec.dataSource == oldObject.spec.dataSource)) && "
            "((!has(object.spec.dataSourceRef) && !has(oldObject.spec.dataSourceRef)) || "
            "(has(object.spec.dataSourceRef) && has(oldObject.spec.dataSourceRef) && object.spec.dataSourceRef == oldObject.spec.dataSourceRef)) && "
            "(object.spec.?volumeName.orValue('') == oldObject.spec.?volumeName.orValue('') || "
            "(oldObject.spec.?volumeName.orValue('') == '' && object.spec.?volumeName.orValue('') != '')))",
            "PersistentVolumeClaim contract is immutable except for its one-time controller binding",
        ),
        _validation(
            "request.operation != 'CREATE' || (size(object.spec.accessModes) >= 1 && "
            "has(object.spec.resources.requests) && 'storage' in object.spec.resources.requests && "
            "(!has(object.spec.volumeMode) || object.spec.volumeMode == 'Filesystem') && !has(object.spec.dataSource) && "
            "!has(object.spec.dataSourceRef) && !has(object.spec.volumeName))",
            "PersistentVolumeClaim must request isolated filesystem storage without a prebound volume or data source",
        ),
    ])

    required_labels = next(
        item["required_labels"] for item in prerequisites["objects"]
        if item["kind"] == "Namespace" and item["name"] == profile["namespace"]
    )
    namespace_expression = " && ".join(
        f"has(object.metadata.labels) && object.metadata.labels[{_q(key)}] == {_q(value)}"
        for key, value in sorted(required_labels.items())
    )
    add("namespace", [""], ["namespaces"], "Cluster", [
        _validation("request.operation != 'DELETE'", "The signed workload namespace cannot be deleted"),
        _validation(f"request.name == {_q(profile['namespace'])}", "Admission policy is bound to one exact workload namespace"),
        _validation("request.operation == 'DELETE' || (" + namespace_expression + ")", "Deployment identity and Restricted Pod Security labels must remain fixed"),
    ], namespaced=False)

    result = {"apiVersion": "v1", "items": items, "kind": "List"}
    validate_admission_document(result, profile, deployment_receipt_sha256)
    return result


def validate_admission_document(
    value: object, profile: dict[str, Any], deployment_receipt_sha256: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {"apiVersion", "items", "kind"}:
        raise AdmissionError("admission resource list fields are invalid")
    if value.get("apiVersion") != "v1" or value.get("kind") != "List" or not isinstance(value.get("items"), list):
        raise AdmissionError("admission resource list envelope is invalid")
    items = value["items"]
    if len(items) != 20:
        raise AdmissionError("admission bundle must contain exactly ten policies and ten bindings")
    policies = [item for item in items if item.get("kind") == "ValidatingAdmissionPolicy"]
    bindings = [item for item in items if item.get("kind") == "ValidatingAdmissionPolicyBinding"]
    if len(policies) != 10 or len(bindings) != 10:
        raise AdmissionError("admission policy/binding inventory is incomplete")
    expected_annotation = {
        "xiaozhi-agent/deployment-id": profile["deployment_id"],
        "xiaozhi-agent/deployment-receipt-sha256": deployment_receipt_sha256,
    }
    policy_names = set()
    for policy in policies:
        if policy.get("apiVersion") != "admissionregistration.k8s.io/v1":
            raise AdmissionError("admission policy API version is not stable v1")
        if policy.get("metadata", {}).get("annotations") != expected_annotation:
            raise AdmissionError("admission policy is not bound to the signed deployment receipt")
        spec = policy.get("spec", {})
        if spec.get("failurePolicy") != "Fail" or not spec.get("validations"):
            raise AdmissionError("admission policy does not fail closed")
        rules = spec.get("matchConstraints", {}).get("resourceRules")
        if not isinstance(rules, list) or len(rules) != 1 or rules[0].get("operations") != ["CREATE", "UPDATE", "DELETE"]:
            raise AdmissionError("admission policy operations are incomplete")
        if not isinstance(spec.get("matchConditions"), list) or len(spec["matchConditions"]) != 1:
            raise AdmissionError("admission policy does not have an exact scope condition")
        name = policy.get("metadata", {}).get("name")
        if not isinstance(name, str) or name in policy_names:
            raise AdmissionError("admission policy name is invalid or duplicated")
        policy_names.add(name)
    for binding in bindings:
        if binding.get("apiVersion") != "admissionregistration.k8s.io/v1" or binding.get("metadata", {}).get("annotations") != expected_annotation:
            raise AdmissionError("admission binding is not stable or receipt-bound")
        spec = binding.get("spec", {})
        if spec.get("policyName") not in policy_names or spec.get("validationActions") != ["Deny", "Audit"]:
            raise AdmissionError("admission binding does not deny and audit through a known policy")


def semantic_allows(
    profile: dict[str, Any], kubernetes: dict[str, Any], prerequisites: dict[str, Any],
    operation: str, resource: dict[str, Any], old_resource: dict[str, Any] | None = None,
) -> bool:
    """Local exact-contract oracle for tests; this is not Kubernetes CEL evaluation."""
    if operation not in {"CREATE", "UPDATE", "DELETE"}:
        return False
    kind = resource.get("kind")
    metadata = resource.get("metadata", {})
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if kind == "Namespace":
        if name != profile["namespace"] or operation == "DELETE":
            return False
        required = next(item["required_labels"] for item in prerequisites["objects"] if item["kind"] == "Namespace" and item["name"] == name)
        labels = metadata.get("labels", {})
        return all(labels.get(key) == value for key, value in required.items())
    if namespace != profile["namespace"]:
        return False
    if kind == "Pod":
        if operation == "DELETE":
            return True
        if operation == "UPDATE" and (old_resource is None or resource.get("spec") != old_resource.get("spec")):
            return False
        labels = metadata.get("labels", {})
        service = labels.get("app.kubernetes.io/component")
        if service not in deployment.SERVICES or labels.get("app.kubernetes.io/instance") != profile["deployment_id"] or labels.get("app.kubernetes.io/part-of") != "xiaozhi-agent-platform":
            return False
        lookup = _resource_map(kubernetes)
        controller_kind = "StatefulSet" if service == "generationcoordinator" else "Deployment"
        expected = lookup[(controller_kind, f"{profile['deployment_id']}-{service}")]["spec"]["template"]["spec"]
        return resource.get("spec") == expected
    expected = _resource_map(kubernetes).get((kind, name))
    if expected is not None:
        if operation == "DELETE":
            return False
        if operation == "UPDATE":
            return old_resource is not None and resource.get("spec") == old_resource.get("spec")
        return resource == expected
    prerequisite = next((item for item in prerequisites["objects"] if item.get("namespace") == namespace and item["kind"] == kind and item["name"] == name), None)
    if prerequisite is None or operation == "DELETE":
        return False
    if operation == "UPDATE":
        if old_resource is None:
            return False
        if kind in {"ConfigMap", "Secret"}:
            return resource.get("data") == old_resource.get("data")
        new_spec = resource.get("spec", {})
        old_spec = old_resource.get("spec", {})
        stable_fields = (
            "accessModes", "resources", "storageClassName", "volumeMode", "selector",
            "dataSource", "dataSourceRef",
        )
        if any(new_spec.get(field) != old_spec.get(field) for field in stable_fields):
            return False
        old_volume = old_spec.get("volumeName", "")
        new_volume = new_spec.get("volumeName", "")
        return new_volume == old_volume or (not old_volume and bool(new_volume))
    if kind in {"ConfigMap", "Secret"}:
        if resource.get("immutable") is not True or resource.get("type", "Opaque") != prerequisite.get("type", "Opaque"):
            return False
        return set(resource.get("data", {})) == set(prerequisite["required_keys"])
    if kind == "PersistentVolumeClaim":
        spec = resource.get("spec", {})
        return bool(spec.get("accessModes")) and "storage" in spec.get("resources", {}).get("requests", {}) and not any(key in spec for key in ("dataSource", "dataSourceRef", "volumeName"))
    return False


def build_bundle(
    *, deployment_bundle: Path, oci_bundle: Path, oci_trusted_public_key: Path,
    oci_signing_key_id: str, expected_oci_release_id: str,
    deployment_trusted_public_key: Path, deployment_signing_key_id: str,
    expected_deployment_id: str, signing_private_key_path: Path,
    signing_key_id: str, output_path: Path,
) -> dict[str, Any]:
    if output_path.exists() or output_path.is_symlink():
        raise AdmissionError("output bundle already exists")
    if not output_path.parent.is_dir():
        raise AdmissionError("output bundle parent does not exist")
    deployment_receipt = deployment.validate_bundle(
        deployment_bundle, oci_bundle=oci_bundle,
        oci_trusted_public_key=oci_trusted_public_key,
        expected_oci_signing_key_id=oci_signing_key_id,
        expected_oci_release_id=expected_oci_release_id,
        trusted_public_key=deployment_trusted_public_key,
        expected_signing_key_id=deployment_signing_key_id,
        expected_deployment_id=expected_deployment_id,
    )
    deployment_receipt_data = oci._read_regular(
        deployment_bundle / "deployment-receipt.json", oci.MAX_JSON_BYTES,
        "deployment receipt",
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
    deployment_receipt_sha256 = oci._sha256(deployment_receipt_data)
    admission_data = oci._json_bytes(build_admission_list(
        profile, kubernetes, prerequisites, deployment_receipt_sha256,
    ))
    signing_key_id = oci._require_identifier(signing_key_id, "admission signing key ID")
    private_key = oci._load_private_key(signing_private_key_path)
    receipt: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "deployment_id": profile["deployment_id"],
        "namespace": profile["namespace"],
        "deployment_receipt_sha256": deployment_receipt_sha256,
        "deployment_signing_key_id": deployment_receipt["signing_key_id"],
        "admission_sha256": oci._sha256(admission_data),
        "policy_count": 10,
        "binding_count": 10,
        "resource_count": 20,
        "signing_key_id": signing_key_id,
        "signature_algorithm": "Ed25519",
    }
    receipt["signature_b64url"] = oci._b64url(private_key.sign(_signature_payload(receipt)))
    receipt_data = oci._json_bytes(receipt)
    created = False
    try:
        output_path.mkdir(mode=0o700)
        created = True
        oci._write_new(output_path / "admission.json", admission_data)
        oci._write_new(output_path / "admission-receipt.json", receipt_data)
        oci._write_new(output_path / "READY", (oci._sha256(receipt_data) + "\n").encode("ascii"))
        oci._fsync_directory(output_path)
        oci._lock_tree(output_path)
    except BaseException:
        if created:
            oci._unlock_tree(output_path)
            shutil.rmtree(output_path)
        raise
    return receipt


def validate_bundle(
    root: Path, *, deployment_bundle: Path, oci_bundle: Path,
    oci_trusted_public_key: Path, expected_oci_signing_key_id: str,
    expected_oci_release_id: str, deployment_trusted_public_key: Path,
    expected_deployment_signing_key_id: str, expected_deployment_id: str,
    trusted_public_key: Path, expected_signing_key_id: str,
) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise AdmissionError("admission bundle must be a non-symlink directory")
    expected_files = {"READY", "admission-receipt.json", "admission.json"}
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise AdmissionError("admission bundle contains a non-regular object")
        if path.stat().st_mode & 0o222:
            raise AdmissionError("admission bundle must be read-only")
        if path.is_file():
            actual_files.add(path.relative_to(root).as_posix())
    if root.stat().st_mode & 0o222 or actual_files != expected_files:
        raise AdmissionError("admission bundle layout or permissions are invalid")
    receipt_data = oci._read_regular(root / "admission-receipt.json", oci.MAX_JSON_BYTES, "admission receipt")
    receipt = oci._strict_json(receipt_data, "admission receipt")
    fields = {
        "schema", "deployment_id", "namespace", "deployment_receipt_sha256",
        "deployment_signing_key_id", "admission_sha256", "policy_count",
        "binding_count", "resource_count", "signing_key_id",
        "signature_algorithm", "signature_b64url",
    }
    if not isinstance(receipt, dict) or set(receipt) != fields or oci._json_bytes(receipt) != receipt_data:
        raise AdmissionError("admission receipt fields or canonical encoding are invalid")
    if receipt.get("schema") != 1 or receipt.get("signature_algorithm") != "Ed25519" or receipt.get("policy_count") != 10 or receipt.get("binding_count") != 10 or receipt.get("resource_count") != 20:
        raise AdmissionError("admission receipt schema or inventory is invalid")
    if receipt.get("deployment_id") != expected_deployment_id or receipt.get("signing_key_id") != expected_signing_key_id:
        raise AdmissionError("admission receipt does not match external trust policy")
    signature = oci._decode_b64url(receipt.get("signature_b64url"), 64, "admission signature")
    try:
        oci._load_public_key(trusted_public_key).verify(signature, _signature_payload(receipt))
    except InvalidSignature as error:
        raise AdmissionError("admission receipt signature is invalid") from error
    ready = oci._read_regular(root / "READY", 128, "admission READY")
    if ready != (oci._sha256(receipt_data) + "\n").encode("ascii"):
        raise AdmissionError("admission READY marker is invalid")
    admission_data = oci._read_regular(root / "admission.json", oci.MAX_JSON_BYTES, "admission resources")
    if receipt.get("admission_sha256") != oci._sha256(admission_data):
        raise AdmissionError("admission content does not match receipt")
    deployment_receipt = deployment.validate_bundle(
        deployment_bundle, oci_bundle=oci_bundle,
        oci_trusted_public_key=oci_trusted_public_key,
        expected_oci_signing_key_id=expected_oci_signing_key_id,
        expected_oci_release_id=expected_oci_release_id,
        trusted_public_key=deployment_trusted_public_key,
        expected_signing_key_id=expected_deployment_signing_key_id,
        expected_deployment_id=expected_deployment_id,
    )
    deployment_receipt_data = oci._read_regular(deployment_bundle / "deployment-receipt.json", oci.MAX_JSON_BYTES, "deployment receipt")
    if receipt.get("deployment_receipt_sha256") != oci._sha256(deployment_receipt_data) or receipt.get("deployment_signing_key_id") != deployment_receipt["signing_key_id"] or receipt.get("namespace") != deployment_receipt["namespace"]:
        raise AdmissionError("admission bundle is not bound to the trusted deployment receipt")
    profile, _ = deployment.load_profile(deployment_bundle / "profile.json")
    kubernetes = oci._strict_json(
        oci._read_regular(deployment_bundle / "kubernetes.json", oci.MAX_JSON_BYTES, "Kubernetes resources"),
        "Kubernetes resources",
    )
    prerequisites = oci._strict_json(
        oci._read_regular(deployment_bundle / "prerequisites.json", oci.MAX_JSON_BYTES, "deployment prerequisites"),
        "deployment prerequisites",
    )
    admission = oci._strict_json(admission_data, "admission resources")
    validate_admission_document(admission, profile, receipt["deployment_receipt_sha256"])
    expected_data = oci._json_bytes(build_admission_list(profile, kubernetes, prerequisites, receipt["deployment_receipt_sha256"]))
    if admission_data != expected_data:
        raise AdmissionError("admission resources violate the deterministic fail-closed contract")
    return receipt
