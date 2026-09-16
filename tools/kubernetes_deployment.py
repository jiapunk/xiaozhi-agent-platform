#!/usr/bin/env python3
"""Signed, deterministic Kubernetes deployment bundle for the product workloads."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
from pathlib import Path
from typing import Any

import oci_release as oci
from cryptography.exceptions import InvalidSignature


SCHEMA_VERSION = 7
SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-KUBERNETES-DEPLOYMENT-V7\x00"
SERVICES = oci.SERVICES
PORTS = {
    "gateway": 8443,
    "controlplane": 8444,
    "agentproxy": 8445,
    "firmwareorigin": 8446,
    "generationcoordinator": 8447,
    "accountauthorization": 9444,
    "factorytimeauthority": 9445,
}
PUBLIC_SERVICES = SERVICES[:4]
EXTERNAL_EGRESS = ("speech", "provider", "identity", "database", "signer")
PROFILE_FIELDS = {
    "schema",
    "agent_usage",
    "speech_usage",
    "service_entitlement",
    "entitlement_update_trust",
    "deployment_id",
    "namespace",
    "registry_repository",
    "image_pull_secret",
    "ingress_namespace",
    "monitoring_namespace",
    "release_operator_namespace",
    "dns_namespace",
    "dns_pod_selector",
    "external_egress",
    "config_maps",
    "secret_env",
    "secret_files",
    "storage_claims",
    "companion_push",
    "telemetry",
}
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
LABEL_KEY = re.compile(
    r"^(?:[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?/)?"
    r"[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$"
)
REGISTRY = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[1-9][0-9]{0,4})?"
    r"/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

CONFIG_KEYS = {
    "gateway": (
        "DEVICE_REGISTRY_URL", "DEVICE_REGISTRY_SIGNING_KEY_ID",
        "DEVICE_REGISTRY_MIN_REVISION", "DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS",
        "DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS",
        "STT_UPSTREAM_URL", "STT_HEALTH_URL", "TTS_UPSTREAM_URL", "TTS_HEALTH_URL",
        "VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION",
        "OUTPUT_SAMPLE_RATE", "OUTPUT_FRAME_MILLIS", "MAX_CONNECTIONS",
        "MAX_MESSAGES_PER_MINUTE", "MAX_AUDIO_PACKETS_PER_MINUTE",
        "OWNERSHIP_DATABASE_MAX_CONNECTIONS", "OWNERSHIP_DATABASE_IDLE_CONNECTIONS",
        "OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS",
        "OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS",
    ),
    "controlplane": (
        "PUBLIC_DEVICE_WSS_URL", "DEVICE_REGISTRY_URL",
        "DEVICE_REGISTRY_SIGNING_KEY_ID", "DEVICE_REGISTRY_MIN_REVISION",
        "DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", "DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS",
        "APP_TOKEN_ED25519_KEYRING", "APP_TOKEN_ISSUER", "APP_TOKEN_MAX_TTL_SECONDS",
        "APP_TOKEN_INTROSPECTION_TIMEOUT_MS",
        "DEVICE_CLAIM_TTL_SECONDS", "DEVICE_CLAIM_MAX_PENDING",
        "VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION",
        "AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION",
        "OTA_TOKEN_HMAC_KEYRING_MIN_REVISION",
        "ACTION_CONSENT_ENABLED", "ACTION_CONSENT_REFERENCE_ENABLED",
        "ACTION_CONSENT_MAX_PENDING", "OWNERSHIP_DATABASE_MAX_CONNECTIONS",
        "OWNERSHIP_DATABASE_IDLE_CONNECTIONS", "OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS",
        "OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS", "OTA_TOKEN_TTL_SECONDS",
        "GENERATION_REPLICA_ID",
    ),
    "agentproxy": (
        "DEVICE_REGISTRY_URL", "DEVICE_REGISTRY_SIGNING_KEY_ID",
        "DEVICE_REGISTRY_MIN_REVISION", "DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS",
        "DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS",
        "AGENT_PROVIDER_URL", "AGENT_PROVIDER_MODEL", "AGENT_PUBLIC_MODEL",
        "AGENT_TOKEN_MAX_TTL_SECONDS", "AGENT_MAX_OUTPUT_TOKENS",
        "AGENT_MAX_REQUEST_KIB", "AGENT_MAX_RESPONSE_KIB",
        "AGENT_REQUEST_TIMEOUT_SECONDS", "AGENT_MAX_CONCURRENT",
        "AGENT_MAX_REQUESTS_PER_MINUTE",
        "AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION",
        "OWNERSHIP_DATABASE_MAX_CONNECTIONS", "OWNERSHIP_DATABASE_IDLE_CONNECTIONS",
        "OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS",
        "OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS",
    ),
    "firmwareorigin": (
        "FIRMWARE_ORIGIN_PUBLIC_AUTHORITY",
        "OTA_TOKEN_MAX_TTL_SECONDS", "FIRMWARE_ORIGIN_MAX_CONCURRENT",
        "FIRMWARE_ORIGIN_WRITE_TIMEOUT_SECONDS", "DEVICE_REGISTRY_URL",
        "DEVICE_REGISTRY_SIGNING_KEY_ID", "DEVICE_REGISTRY_MIN_REVISION",
        "DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", "DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS",
        "GENERATION_REPLICA_ID",
        "OTA_TOKEN_HMAC_KEYRING_MIN_REVISION",
    ),
    "generationcoordinator": (
        "GENERATION_PUBLISHER_ID", "GENERATION_PREPARE_TIMEOUT_SECONDS",
        "GENERATION_COMMIT_TIMEOUT_SECONDS", "GENERATION_MAX_CLOCK_SKEW_SECONDS",
    ),
    "accountauthorization": (
        "ACCOUNT_AUTHORIZATION_DATABASE_MAX_OPEN",
        "ACCOUNT_AUTHORIZATION_DATABASE_MAX_IDLE",
        "ACCOUNT_AUTHORIZATION_DATABASE_CONN_TTL_SECONDS",
        "ACCOUNT_AUTHORIZATION_DATABASE_TIMEOUT_MS",
        "ACCOUNT_AUTHORIZATION_SHUTDOWN_TIMEOUT_SECONDS",
    ),
    "factorytimeauthority": (
        "FACTORY_TIME_DATABASE_MAX_OPEN", "FACTORY_TIME_DATABASE_MAX_IDLE",
        "FACTORY_TIME_DATABASE_CONN_TTL_SECONDS", "FACTORY_TIME_DATABASE_TIMEOUT_MS",
        "FACTORY_TIME_RECEIPT_LIFETIME_SECONDS", "FACTORY_TIME_SIGNER_ENDPOINT",
        "FACTORY_TIME_SIGNER_KEY_ID", "FACTORY_TIME_SIGNER_PUBLIC_KEY_SHA256",
        "FACTORY_TIME_SIGNER_CA_SHA256", "FACTORY_TIME_SIGNER_CLIENT_CERT_SHA256",
        "FACTORY_TIME_SIGNER_TIMEOUT_MS", "FACTORY_TIME_SHUTDOWN_TIMEOUT_SECONDS",
    ),
}

SECRET_ENV_KEYS = {
    "gateway": ("STT_UPSTREAM_TOKEN", "TTS_UPSTREAM_TOKEN", "OWNERSHIP_DATABASE_URL"),
    "controlplane": (
        "OTA_ROLLOUT_HMAC_KEY_B64",
        "OWNERSHIP_DATABASE_URL", "GENERATION_REPLICA_HMAC_KEY_B64",
    ),
    "agentproxy": ("AGENT_PROVIDER_API_KEY", "OWNERSHIP_DATABASE_URL"),
    "firmwareorigin": ("GENERATION_REPLICA_HMAC_KEY_B64",),
    "generationcoordinator": ("GENERATION_STATE_HMAC_KEY_B64", "GENERATION_PUBLISHER_HMAC_KEY_B64"),
    "accountauthorization": ("ACCOUNT_AUTHORIZATION_DATABASE_URL",),
    "factorytimeauthority": ("FACTORY_TIME_DATABASE_URL",),
}

SECRET_FILE_KEYS = {
    "gateway": (
        "tls.crt", "tls.key", "identity-ca.pem", "identity-client.crt",
        "identity-client.key", "identity-signing.pub", "stt-ca.pem",
        "stt-client.crt", "stt-client.key", "tts-ca.pem", "tts-client.crt",
        "tts-client.key",
        "voice-token-keyring.json",
        "speech-usage-digest.key",
    ),
    "controlplane": (
        "tls.crt", "tls.key", "identity-ca.pem", "identity-client.crt",
        "identity-client.key", "identity-signing.pub", "companion-ca.pem",
        "companion-client.crt", "companion-client.key",
        "voice-token-keyring.json", "agent-token-keyring.json",
        "ota-token-keyring.json",
    ),
    "agentproxy": (
        "tls.crt", "tls.key", "identity-ca.pem", "identity-client.crt",
        "identity-client.key", "identity-signing.pub", "agent-token-keyring.json",
        "usage-digest.key",
    ),
    "firmwareorigin": (
        "tls.crt", "tls.key", "identity-ca.pem", "identity-client.crt",
        "identity-client.key", "identity-signing.pub", "ota-token-keyring.json",
    ),
    "generationcoordinator": ("tls.crt", "tls.key", "generation-replicas.json"),
    "accountauthorization": (
        "tls.crt", "tls.key", "control-client-ca.pem",
        "entitlement-update-keyring.json",
    ),
    "factorytimeauthority": (
        "tls.crt", "tls.key", "station-client-ca.pem", "signer.pub",
        "signer-ca.pem", "signer-client.crt", "signer-client.key",
    ),
}

RESOURCES = {
    "gateway": ("250m", "256Mi", "2", "1Gi"),
    "controlplane": ("200m", "256Mi", "1", "768Mi"),
    "agentproxy": ("200m", "256Mi", "2", "1Gi"),
    "firmwareorigin": ("100m", "128Mi", "1", "512Mi"),
    "generationcoordinator": ("100m", "128Mi", "500m", "512Mi"),
    "accountauthorization": ("100m", "128Mi", "1", "512Mi"),
    "factorytimeauthority": ("100m", "128Mi", "1", "512Mi"),
}


class DeploymentError(ValueError):
    pass


def _name(value: object, label: str, maximum: int = 63) -> str:
    if not isinstance(value, str) or len(value) > maximum or not DNS_LABEL.fullmatch(value):
        raise DeploymentError(f"{label} must be a canonical DNS label")
    return value


def _exact_map(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(SERVICES):
        raise DeploymentError(f"{label} must contain the exact seven-service set")
    result = {service: _name(value[service], f"{label}.{service}") for service in SERVICES}
    if len(set(result.values())) != len(result):
        raise DeploymentError(f"{label} names must be isolated per service")
    return result


def _cidrs(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise DeploymentError(f"{label} must contain 1 through 32 CIDRs")
    result: list[str] = []
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in value:
        if not isinstance(raw, str):
            raise DeploymentError(f"{label} contains a non-string CIDR")
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as error:
            raise DeploymentError(f"{label} contains a noncanonical CIDR") from error
        if str(network) != raw or network.is_unspecified or network.is_multicast or network.is_loopback or network.is_link_local:
            raise DeploymentError(f"{label} contains an unsafe CIDR")
        if (network.version == 4 and network.prefixlen < 8) or (network.version == 6 and network.prefixlen < 32):
            raise DeploymentError(f"{label} CIDRs must be narrower than a default egress route")
        if any(network.overlaps(existing) for existing in networks):
            raise DeploymentError(f"{label} CIDRs must not overlap")
        networks.append(network)
        result.append(raw)
    if result != sorted(result):
        raise DeploymentError(f"{label} CIDRs must be uniquely sorted")
    return tuple(result)


def validate_profile(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS or value.get("schema") != SCHEMA_VERSION:
        raise DeploymentError("deployment profile fields or schema are invalid")
    deployment_id = _name(value["deployment_id"], "deployment ID", 32)
    namespace = _name(value["namespace"], "namespace")
    registry = value["registry_repository"]
    if not isinstance(registry, str) or len(registry) > 255 or not REGISTRY.fullmatch(registry):
        raise DeploymentError("registry repository must be a canonical lowercase host/path")
    host = registry.split("/", 1)[0]
    if ":" in host and int(host.rsplit(":", 1)[1]) > 65535:
        raise DeploymentError("registry port is outside range")
    namespaces = {
        role: _name(value[f"{role}_namespace"], f"{role} namespace")
        for role in ("ingress", "monitoring", "release_operator", "dns")
    }
    if len({namespace, *namespaces.values()}) != 5:
        raise DeploymentError("workload and infrastructure namespaces must be distinct")
    selector = value["dns_pod_selector"]
    if not isinstance(selector, dict) or not 1 <= len(selector) <= 4:
        raise DeploymentError("DNS pod selector must contain 1 through 4 labels")
    for key, selector_value in selector.items():
        if not isinstance(key, str) or not LABEL_KEY.fullmatch(key) or not isinstance(selector_value, str) or len(selector_value) > 63:
            raise DeploymentError("DNS pod selector labels are invalid")
    external = value["external_egress"]
    if not isinstance(external, dict) or set(external) != set(EXTERNAL_EGRESS):
        raise DeploymentError("external egress must contain the exact five dependency classes")
    normalized_external = {key: _cidrs(external[key], f"external egress {key}") for key in EXTERNAL_EGRESS}
    classified: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for dependency in EXTERNAL_EGRESS:
        for raw in normalized_external[dependency]:
            network = ipaddress.ip_network(raw, strict=True)
            for prior_dependency, prior in classified:
                if network.overlaps(prior):
                    raise DeploymentError(
                        f"external egress CIDRs overlap across {prior_dependency} and {dependency}"
                    )
            classified.append((dependency, network))
    storage = value["storage_claims"]
    if not isinstance(storage, dict) or set(storage) != {"controlplane_bundle", "firmwareorigin_bundle", "generation_state"}:
        raise DeploymentError("storage claims are incomplete")
    normalized_storage = {key: _name(raw, f"storage claim {key}") for key, raw in storage.items()}
    if len(set(normalized_storage.values())) != 3:
        raise DeploymentError("storage claims must be isolated")
    companion_push = value["companion_push"]
    if not isinstance(companion_push, dict) or set(companion_push) != {
        "enabled", "apns", "fcm_credential_mode"
    }:
        raise DeploymentError("Companion push profile fields are invalid")
    enabled = companion_push["enabled"]
    apns = companion_push["apns"]
    fcm_mode = companion_push["fcm_credential_mode"]
    if not isinstance(enabled, bool) or not isinstance(apns, bool) or fcm_mode not in {
        "disabled", "metadata", "service-account"
    }:
        raise DeploymentError("Companion push profile values are invalid")
    if enabled and not apns and fcm_mode == "disabled":
        raise DeploymentError("enabled Companion push requires at least one provider")
    if not enabled and (apns or fcm_mode != "disabled"):
        raise DeploymentError("disabled Companion push cannot configure providers")
    agent_usage = value["agent_usage"]
    if not isinstance(agent_usage, dict) or set(agent_usage) != {
        "pricing_profile_id", "input_microusd_per_million_tokens",
        "output_microusd_per_million_tokens", "daily_budget_microusd",
        "input_token_overhead", "reservation_ttl_seconds",
    }:
        raise DeploymentError("Agent usage pricing profile fields are invalid")
    profile_id = agent_usage["pricing_profile_id"]
    if not isinstance(profile_id, str) or not IDENTIFIER.fullmatch(profile_id):
        raise DeploymentError("Agent usage pricing profile ID is invalid")
    numeric_agent_usage = {
        "input_microusd_per_million_tokens": (1, 1_000_000_000_000),
        "output_microusd_per_million_tokens": (1, 1_000_000_000_000),
        "daily_budget_microusd": (1, 1_000_000_000_000_000),
        "input_token_overhead": (0, 65_536),
        "reservation_ttl_seconds": (30, 600),
    }
    for field, (minimum, maximum) in numeric_agent_usage.items():
        number = agent_usage[field]
        if isinstance(number, bool) or not isinstance(number, int) or \
                number < minimum or number > maximum:
            raise DeploymentError(f"Agent usage {field} is invalid")
    speech_usage = value["speech_usage"]
    if not isinstance(speech_usage, dict) or set(speech_usage) != {
        "pricing_profile_id", "stt_microusd_per_million_audio_ms",
        "tts_microusd_per_million_characters",
        "tts_microusd_per_million_output_audio_ms",
        "daily_budget_microusd", "stt_reservation_chunk_audio_ms",
        "tts_max_output_audio_ms", "reservation_ttl_seconds",
    }:
        raise DeploymentError("speech usage pricing profile fields are invalid")
    speech_profile_id = speech_usage["pricing_profile_id"]
    if not isinstance(speech_profile_id, str) or not IDENTIFIER.fullmatch(
            speech_profile_id):
        raise DeploymentError("speech usage pricing profile ID is invalid")
    numeric_speech_usage = {
        "stt_microusd_per_million_audio_ms": (1, 1_000_000_000_000),
        "tts_microusd_per_million_characters": (0, 1_000_000_000_000),
        "tts_microusd_per_million_output_audio_ms": (0, 1_000_000_000_000),
        "daily_budget_microusd": (1, 1_000_000_000_000_000),
        "stt_reservation_chunk_audio_ms": (1_000, 60_000),
        "tts_max_output_audio_ms": (1_000, 600_000),
        "reservation_ttl_seconds": (60, 600),
    }
    for field, (minimum, maximum) in numeric_speech_usage.items():
        number = speech_usage[field]
        if isinstance(number, bool) or not isinstance(number, int) or \
                number < minimum or number > maximum:
            raise DeploymentError(f"speech usage {field} is invalid")
    if speech_usage["tts_microusd_per_million_characters"] == 0 and \
            speech_usage["tts_microusd_per_million_output_audio_ms"] == 0:
        raise DeploymentError("speech usage requires at least one TTS billing dimension")
    service_entitlement = value["service_entitlement"]
    if not isinstance(service_entitlement, dict) or set(service_entitlement) != {
        "voice_token_ttl_seconds", "agent_token_ttl_seconds"
    }:
        raise DeploymentError("service entitlement profile fields are invalid")
    for field in ("voice_token_ttl_seconds", "agent_token_ttl_seconds"):
        number = service_entitlement[field]
        if isinstance(number, bool) or not isinstance(number, int) or \
                number < 60 or number > 900:
            raise DeploymentError(f"service entitlement {field} is invalid")
    entitlement_update_trust = value["entitlement_update_trust"]
    if not isinstance(entitlement_update_trust, dict) or \
            set(entitlement_update_trust) != {
                "keyring_min_revision", "authorization_ttl_seconds"
            }:
        raise DeploymentError("entitlement update trust profile fields are invalid")
    keyring_min_revision = entitlement_update_trust["keyring_min_revision"]
    authorization_ttl_seconds = entitlement_update_trust[
        "authorization_ttl_seconds"
    ]
    if isinstance(keyring_min_revision, bool) or \
            not isinstance(keyring_min_revision, int) or \
            keyring_min_revision < 1 or \
            keyring_min_revision > 9_007_199_254_740_991:
        raise DeploymentError("entitlement update keyring_min_revision is invalid")
    if isinstance(authorization_ttl_seconds, bool) or \
            not isinstance(authorization_ttl_seconds, int) or \
            authorization_ttl_seconds < 60 or authorization_ttl_seconds > 300:
        raise DeploymentError("entitlement update authorization_ttl_seconds is invalid")
    telemetry = value["telemetry"]
    if not isinstance(telemetry, dict) or set(telemetry) != {
        "collector_service", "pod_selector", "sample_ratio_ppm", "timeout_ms"
    }:
        raise DeploymentError("telemetry profile fields are invalid")
    telemetry_selector = telemetry["pod_selector"]
    if not isinstance(telemetry_selector, dict) or not 1 <= len(telemetry_selector) <= 4:
        raise DeploymentError("telemetry pod selector must contain 1 through 4 labels")
    for key, selector_value in telemetry_selector.items():
        if not isinstance(key, str) or not LABEL_KEY.fullmatch(key) or \
                not isinstance(selector_value, str) or len(selector_value) > 63:
            raise DeploymentError("telemetry pod selector labels are invalid")
    sample_ratio = telemetry["sample_ratio_ppm"]
    timeout_ms = telemetry["timeout_ms"]
    if isinstance(sample_ratio, bool) or not isinstance(sample_ratio, int) or \
            sample_ratio < 1 or sample_ratio > 1_000_000:
        raise DeploymentError("telemetry sample ratio is invalid")
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or \
            timeout_ms < 100 or timeout_ms > 5_000:
        raise DeploymentError("telemetry timeout is invalid")
    return {
        **value,
        "deployment_id": deployment_id,
        "namespace": namespace,
        "registry_repository": registry,
        "image_pull_secret": _name(value["image_pull_secret"], "image pull secret"),
        **{f"{role}_namespace": name for role, name in namespaces.items()},
        "dns_pod_selector": dict(sorted(selector.items())),
        "external_egress": normalized_external,
        "config_maps": _exact_map(value["config_maps"], "config maps"),
        "secret_env": _exact_map(value["secret_env"], "environment secrets"),
        "secret_files": _exact_map(value["secret_files"], "file secrets"),
        "storage_claims": normalized_storage,
        "companion_push": {
            "enabled": enabled,
            "apns": apns,
            "fcm_credential_mode": fcm_mode,
        },
        "agent_usage": {
            "pricing_profile_id": profile_id,
            **{field: agent_usage[field] for field in numeric_agent_usage},
        },
        "speech_usage": {
            "pricing_profile_id": speech_profile_id,
            **{field: speech_usage[field] for field in numeric_speech_usage},
        },
        "service_entitlement": {
            "voice_token_ttl_seconds":
                service_entitlement["voice_token_ttl_seconds"],
            "agent_token_ttl_seconds":
                service_entitlement["agent_token_ttl_seconds"],
        },
        "entitlement_update_trust": {
            "keyring_min_revision": keyring_min_revision,
            "authorization_ttl_seconds": authorization_ttl_seconds,
        },
        "telemetry": {
            "collector_service": _name(
                telemetry["collector_service"], "telemetry collector service"
            ),
            "pod_selector": dict(sorted(telemetry_selector.items())),
            "sample_ratio_ppm": sample_ratio,
            "timeout_ms": timeout_ms,
        },
    }


def load_profile(path: Path) -> tuple[dict[str, Any], bytes]:
    data = oci._read_regular(path, oci.MAX_JSON_BYTES, "deployment profile")
    value = oci._strict_json(data, "deployment profile")
    if oci._json_bytes(value) != data:
        raise DeploymentError("deployment profile must be canonical JSON")
    return validate_profile(value), data


def _labels(profile: dict[str, Any], service: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/component": service,
        "app.kubernetes.io/instance": profile["deployment_id"],
        "app.kubernetes.io/name": service,
        "app.kubernetes.io/part-of": "xiaozhi-agent-platform",
    }


def _resource_name(profile: dict[str, Any], service: str) -> str:
    return f"{profile['deployment_id']}-{service}"


def _fixed_env(profile: dict[str, Any], service: str) -> list[dict[str, Any]]:
    secret_root = "/run/secrets/files"
    common = [
        {"name": "TELEMETRY_OTLP_TRACES_ENDPOINT", "value":
            f"https://{profile['telemetry']['collector_service']}."
            f"{profile['monitoring_namespace']}.svc:4318/v1/traces"},
        {"name": "TELEMETRY_DEPLOYMENT_ID", "value": profile["deployment_id"]},
        {"name": "TELEMETRY_OTLP_CA_FILE", "value":
            f"{secret_root}/telemetry-ca.pem"},
        {"name": "TELEMETRY_OTLP_CLIENT_CERT_FILE", "value":
            f"{secret_root}/telemetry-client.crt"},
        {"name": "TELEMETRY_OTLP_CLIENT_KEY_FILE", "value":
            f"{secret_root}/telemetry-client.key"},
        {"name": "TELEMETRY_TRACE_SAMPLE_RATIO_PPM", "value":
            str(profile["telemetry"]["sample_ratio_ppm"])},
        {"name": "TELEMETRY_OTLP_TIMEOUT_MS", "value":
            str(profile["telemetry"]["timeout_ms"])},
    ]
    if service not in {"accountauthorization", "factorytimeauthority"}:
        common.insert(0, {"name": "ALLOW_INSECURE_DEVELOPMENT", "value": "false"})
    values = {
        "gateway": {
            "GATEWAY_ADDRESS": ":8443", "TLS_CERT_FILE": f"{secret_root}/tls.crt",
            "TLS_KEY_FILE": f"{secret_root}/tls.key", "ENABLE_SESSION_ISSUANCE": "false",
            "STT_TLS_CA_FILE": f"{secret_root}/stt-ca.pem",
            "STT_TLS_CLIENT_CERT_FILE": f"{secret_root}/stt-client.crt",
            "STT_TLS_CLIENT_KEY_FILE": f"{secret_root}/stt-client.key",
            "TTS_TLS_CA_FILE": f"{secret_root}/tts-ca.pem",
            "TTS_TLS_CLIENT_CERT_FILE": f"{secret_root}/tts-client.crt",
            "TTS_TLS_CLIENT_KEY_FILE": f"{secret_root}/tts-client.key",
            "VOICE_TOKEN_HMAC_KEYRING_FILE":
                f"{secret_root}/voice-token-keyring.json",
            "DEVICE_TOKEN_MAX_TTL_SECONDS": str(
                profile["service_entitlement"]["voice_token_ttl_seconds"]),
            "SPEECH_PRICING_PROFILE_ID":
                profile["speech_usage"]["pricing_profile_id"],
            "SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS": str(
                profile["speech_usage"]["stt_microusd_per_million_audio_ms"]),
            "SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS": str(
                profile["speech_usage"]["tts_microusd_per_million_characters"]),
            "SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS": str(
                profile["speech_usage"]["tts_microusd_per_million_output_audio_ms"]),
            "SPEECH_DAILY_BUDGET_MICROUSD": str(
                profile["speech_usage"]["daily_budget_microusd"]),
            "SPEECH_STT_RESERVATION_CHUNK_AUDIO_MS": str(
                profile["speech_usage"]["stt_reservation_chunk_audio_ms"]),
            "SPEECH_TTS_MAX_OUTPUT_AUDIO_MS": str(
                profile["speech_usage"]["tts_max_output_audio_ms"]),
            "SPEECH_USAGE_RESERVATION_TTL_SECONDS": str(
                profile["speech_usage"]["reservation_ttl_seconds"]),
            "SPEECH_USAGE_DIGEST_KEY_FILE":
                f"{secret_root}/speech-usage-digest.key",
        },
        "controlplane": {
            "CONTROL_PLANE_ADDRESS": ":8444", "CONTROL_TLS_CERT_FILE": f"{secret_root}/tls.crt",
            "CONTROL_TLS_KEY_FILE": f"{secret_root}/tls.key",
            "APP_TOKEN_INTROSPECTION_URL":
                f"https://{_resource_name(profile, 'accountauthorization')}:9444/v1/companion-tokens/introspect",
            "SERVICE_ENTITLEMENT_AUTHORIZATION_URL":
                f"https://{_resource_name(profile, 'accountauthorization')}:9444/v1/service-entitlements/authorize",
            "APP_TOKEN_INTROSPECTION_CA_FILE": f"{secret_root}/companion-ca.pem",
            "APP_TOKEN_INTROSPECTION_CLIENT_CERT_FILE": f"{secret_root}/companion-client.crt",
            "APP_TOKEN_INTROSPECTION_CLIENT_KEY_FILE": f"{secret_root}/companion-client.key",
            "GENERATION_COORDINATOR_URL":
                f"https://{_resource_name(profile, 'generationcoordinator')}:8447",
            "OTA_DEPLOYMENT_BUNDLE_ROOT": "/run/ota-bundle",
            "OTA_RELEASE_REGISTRY_FILE": "/run/ota-bundle/control/ota-release-registry.json",
            "VOICE_TOKEN_HMAC_KEYRING_FILE":
                f"{secret_root}/voice-token-keyring.json",
            "AGENT_TOKEN_HMAC_KEYRING_FILE":
                f"{secret_root}/agent-token-keyring.json",
            "OTA_TOKEN_HMAC_KEYRING_FILE":
                f"{secret_root}/ota-token-keyring.json",
            "VOICE_TOKEN_TTL_SECONDS": str(
                profile["service_entitlement"]["voice_token_ttl_seconds"]),
            "AGENT_TOKEN_TTL_SECONDS": str(
                profile["service_entitlement"]["agent_token_ttl_seconds"]),
        },
        "agentproxy": {
            "AGENT_PROXY_ADDRESS": ":8445", "AGENT_PROXY_TLS_CERT_FILE": f"{secret_root}/tls.crt",
            "AGENT_PROXY_TLS_KEY_FILE": f"{secret_root}/tls.key",
            "AGENT_TOKEN_HMAC_KEYRING_FILE":
                f"{secret_root}/agent-token-keyring.json",
            "AGENT_TOKEN_MAX_TTL_SECONDS": str(
                profile["service_entitlement"]["agent_token_ttl_seconds"]),
            "AGENT_PRICING_PROFILE_ID":
                profile["agent_usage"]["pricing_profile_id"],
            "AGENT_INPUT_MICROUSD_PER_MILLION_TOKENS": str(
                profile["agent_usage"]["input_microusd_per_million_tokens"]),
            "AGENT_OUTPUT_MICROUSD_PER_MILLION_TOKENS": str(
                profile["agent_usage"]["output_microusd_per_million_tokens"]),
            "AGENT_DAILY_BUDGET_MICROUSD": str(
                profile["agent_usage"]["daily_budget_microusd"]),
            "AGENT_INPUT_TOKEN_OVERHEAD": str(
                profile["agent_usage"]["input_token_overhead"]),
            "AGENT_USAGE_RESERVATION_TTL_SECONDS": str(
                profile["agent_usage"]["reservation_ttl_seconds"]),
            "AGENT_USAGE_DIGEST_KEY_FILE": f"{secret_root}/usage-digest.key",
        },
        "firmwareorigin": {
            "FIRMWARE_ORIGIN_ADDRESS": ":8446", "FIRMWARE_ORIGIN_TLS_CERT_FILE": f"{secret_root}/tls.crt",
            "FIRMWARE_ORIGIN_TLS_KEY_FILE": f"{secret_root}/tls.key",
            "FIRMWARE_ORIGIN_CATALOG_FILE":
                "/run/ota-bundle/origin/firmware-origin-catalog.json",
            "GENERATION_COORDINATOR_URL":
                f"https://{_resource_name(profile, 'generationcoordinator')}:8447",
            "OTA_DEPLOYMENT_BUNDLE_ROOT": "/run/ota-bundle",
            "OTA_TOKEN_HMAC_KEYRING_FILE":
                f"{secret_root}/ota-token-keyring.json",
        },
        "generationcoordinator": {
            "GENERATION_COORDINATOR_ADDRESS": ":8447",
            "GENERATION_COORDINATOR_TLS_CERT_FILE": f"{secret_root}/tls.crt",
            "GENERATION_COORDINATOR_TLS_KEY_FILE": f"{secret_root}/tls.key",
            "GENERATION_STATE_DIRECTORY": "/var/lib/xiaozhi-generation",
            "GENERATION_REPLICA_REGISTRY_FILE": f"{secret_root}/generation-replicas.json",
        },
        "accountauthorization": {
            "ACCOUNT_AUTHORIZATION_LISTEN_ADDR": ":9444",
            "ACCOUNT_AUTHORIZATION_HEALTH_LISTEN_ADDR": ":9080",
            "ACCOUNT_AUTHORIZATION_CLIENT_CA_FILE": f"{secret_root}/control-client-ca.pem",
            "ACCOUNT_AUTHORIZATION_SERVER_CERT_FILE": f"{secret_root}/tls.crt",
            "ACCOUNT_AUTHORIZATION_SERVER_KEY_FILE": f"{secret_root}/tls.key",
            "ENTITLEMENT_UPDATE_KEYRING_FILE":
                f"{secret_root}/entitlement-update-keyring.json",
            "ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION": str(
                profile["entitlement_update_trust"]["keyring_min_revision"]),
            "ENTITLEMENT_UPDATE_AUTHORIZATION_TTL_SECONDS": str(
                profile["entitlement_update_trust"]["authorization_ttl_seconds"]),
        },
        "factorytimeauthority": {
            "FACTORY_TIME_LISTEN_ADDR": ":9445",
            "FACTORY_TIME_HEALTH_LISTEN_ADDR": ":9081",
            "FACTORY_TIME_STATION_CLIENT_CA_FILE": f"{secret_root}/station-client-ca.pem",
            "FACTORY_TIME_SERVER_CERT_FILE": f"{secret_root}/tls.crt",
            "FACTORY_TIME_SERVER_KEY_FILE": f"{secret_root}/tls.key",
            "FACTORY_TIME_SIGNER_PUBLIC_KEY_FILE": f"{secret_root}/signer.pub",
            "FACTORY_TIME_SIGNER_CA_FILE": f"{secret_root}/signer-ca.pem",
            "FACTORY_TIME_SIGNER_CLIENT_CERT_FILE": f"{secret_root}/signer-client.crt",
            "FACTORY_TIME_SIGNER_CLIENT_KEY_FILE": f"{secret_root}/signer-client.key",
        },
    }
    if service in {"gateway", "controlplane", "agentproxy", "firmwareorigin"}:
        values[service].update({
            "DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE": f"{secret_root}/identity-signing.pub",
            "DEVICE_REGISTRY_TLS_CA_FILE": f"{secret_root}/identity-ca.pem",
            "DEVICE_REGISTRY_TLS_CERT_FILE": f"{secret_root}/identity-client.crt",
            "DEVICE_REGISTRY_TLS_KEY_FILE": f"{secret_root}/identity-client.key",
        })
    if profile["companion_push"]["enabled"]:
        if service == "controlplane":
            values[service]["ACTION_CONSENT_PUSH_ENABLED"] = "true"
        elif service == "accountauthorization":
            values[service]["COMPANION_PUSH_ENABLED"] = "true"
            values[service]["COMPANION_PUSH_TOKEN_KEYRING_FILE"] = (
                f"{secret_root}/push-token-keyring.json"
            )
            if profile["companion_push"]["apns"]:
                values[service]["COMPANION_PUSH_APNS_PRIVATE_KEY_FILE"] = (
                    f"{secret_root}/apns-private-key.p8"
                )
            if profile["companion_push"]["fcm_credential_mode"] == "service-account":
                values[service]["COMPANION_PUSH_FCM_SERVICE_ACCOUNT_FILE"] = (
                    f"{secret_root}/fcm-service-account.json"
                )
            if profile["companion_push"]["fcm_credential_mode"] != "disabled":
                values[service]["COMPANION_PUSH_FCM_CREDENTIAL_MODE"] = (
                    profile["companion_push"]["fcm_credential_mode"]
                )
    result: list[dict[str, Any]] = common + [
        {"name": key, "value": value} for key, value in values[service].items()
    ]
    if service in {"gateway", "controlplane", "agentproxy"}:
        result.append({
            "name": "RUNTIME_COORDINATION_WORKER_ID",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
        })
    if service == "controlplane" and profile["companion_push"]["enabled"]:
        result.append({
            "name": "ACTION_CONSENT_PUSH_WORKER_ID",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}},
        })
    return result


def _config_keys(profile: dict[str, Any], service: str) -> tuple[str, ...]:
    keys = list(CONFIG_KEYS[service])
    if profile["companion_push"]["enabled"]:
        if service == "controlplane":
            keys.extend((
                "ACTION_CONSENT_PUSH_POLL_MS", "ACTION_CONSENT_PUSH_LEASE_MS",
                "ACTION_CONSENT_PUSH_RETRY_MS",
                "ACTION_CONSENT_PUSH_REQUEST_TIMEOUT_MS",
            ))
        elif service == "accountauthorization":
            keys.append("COMPANION_PUSH_PROVIDER_TIMEOUT_MS")
            if profile["companion_push"]["apns"]:
                keys.extend((
                    "COMPANION_PUSH_APNS_TOPIC", "COMPANION_PUSH_APNS_KEY_ID",
                    "COMPANION_PUSH_APNS_TEAM_ID",
                ))
            if profile["companion_push"]["fcm_credential_mode"] != "disabled":
                keys.append("COMPANION_PUSH_FCM_PROJECT_ID")
    return tuple(keys)


def _secret_file_keys(profile: dict[str, Any], service: str) -> tuple[str, ...]:
    keys = list(SECRET_FILE_KEYS[service])
    keys.extend((
        "telemetry-ca.pem", "telemetry-client.crt", "telemetry-client.key",
    ))
    if service == "accountauthorization" and profile["companion_push"]["enabled"]:
        keys.append("push-token-keyring.json")
        if profile["companion_push"]["apns"]:
            keys.append("apns-private-key.p8")
        if profile["companion_push"]["fcm_credential_mode"] == "service-account":
            keys.append("fcm-service-account.json")
    return tuple(keys)


def _pod_spec(profile: dict[str, Any], service: str, image: str) -> dict[str, Any]:
    primary_port = PORTS[service]
    private_probe_ports = {"accountauthorization": 9080, "factorytimeauthority": 9081}
    probe_port = private_probe_ports.get(service, primary_port)
    probe_scheme = "HTTP" if service in private_probe_ports else "HTTPS"
    request_cpu, request_memory, limit_cpu, limit_memory = RESOURCES[service]
    volumes: list[dict[str, Any]] = [{
        "name": "service-files",
        "secret": {
            "defaultMode": 256,
            "items": [
                {"key": key, "mode": 256, "path": key}
                for key in _secret_file_keys(profile, service)
            ],
            "optional": False,
            "secretName": profile["secret_files"][service],
        },
    }]
    mounts: list[dict[str, Any]] = [{"mountPath": "/run/secrets/files", "name": "service-files", "readOnly": True}]
    digest_subpaths = {
        "gateway": "speech-usage-digest.key",
        "agentproxy": "usage-digest.key",
        "accountauthorization": "entitlement-update-keyring.json",
    }
    if service in digest_subpaths:
        digest_name = digest_subpaths[service]
        mounts.append({
            "mountPath": f"/run/secrets/files/{digest_name}",
            "name": "service-files",
            "readOnly": True,
            "subPath": digest_name,
        })
    if service == "controlplane":
        volumes.append({"name": "ota-bundle", "persistentVolumeClaim": {"claimName": profile["storage_claims"]["controlplane_bundle"], "readOnly": True}})
        mounts.append({"mountPath": "/run/ota-bundle", "name": "ota-bundle", "readOnly": True})
    elif service == "firmwareorigin":
        volumes.append({"name": "ota-bundle", "persistentVolumeClaim": {"claimName": profile["storage_claims"]["firmwareorigin_bundle"], "readOnly": True}})
        mounts.append({"mountPath": "/run/ota-bundle", "name": "ota-bundle", "readOnly": True})
    elif service == "generationcoordinator":
        volumes.append({"name": "generation-state", "persistentVolumeClaim": {"claimName": profile["storage_claims"]["generation_state"], "readOnly": False}})
        mounts.append({"mountPath": "/var/lib/xiaozhi-generation", "name": "generation-state", "readOnly": False})
    ports = [{"containerPort": primary_port, "name": "https", "protocol": "TCP"}]
    if service in private_probe_ports:
        ports.append({"containerPort": probe_port, "name": "health", "protocol": "TCP"})
    probe = {"httpGet": {"path": "/healthz", "port": probe_port, "scheme": probe_scheme}, "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 3}
    readiness = {"httpGet": {"path": "/readyz", "port": probe_port, "scheme": probe_scheme}, "periodSeconds": 5, "timeoutSeconds": 2, "failureThreshold": 2, "successThreshold": 1}
    container = {
        "env": _fixed_env(profile, service),
        "envFrom": [
            {"configMapRef": {"name": profile["config_maps"][service], "optional": False}},
            {"secretRef": {"name": profile["secret_env"][service], "optional": False}},
        ],
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "livenessProbe": probe,
        "name": service,
        "ports": ports,
        "readinessProbe": readiness,
        "resources": {
            "limits": {"cpu": limit_cpu, "memory": limit_memory},
            "requests": {"cpu": request_cpu, "memory": request_memory},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
            "privileged": False, "readOnlyRootFilesystem": True,
            "runAsGroup": 65532, "runAsNonRoot": True, "runAsUser": 65532,
        },
        "startupProbe": {**probe, "failureThreshold": 30},
        "volumeMounts": mounts,
    }
    return {
        "automountServiceAccountToken": False,
        "containers": [container],
        "dnsPolicy": "ClusterFirst",
        "enableServiceLinks": False,
        "hostIPC": False, "hostNetwork": False, "hostPID": False,
        "imagePullSecrets": [{"name": profile["image_pull_secret"]}],
        "nodeSelector": {"kubernetes.io/os": "linux"},
        "restartPolicy": "Always",
        "securityContext": {
            "fsGroup": 65532, "fsGroupChangePolicy": "OnRootMismatch",
            "runAsGroup": 65532, "runAsNonRoot": True, "runAsUser": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "serviceAccountName": _resource_name(profile, service),
        "terminationGracePeriodSeconds": 30 if service == "firmwareorigin" else 15,
        "volumes": volumes,
    }


def _metadata(profile: dict[str, Any], name: str, labels: dict[str, str]) -> dict[str, Any]:
    return {"labels": labels, "name": name, "namespace": profile["namespace"]}


def _network_policy(profile: dict[str, Any], name: str, selector: dict[str, Any], *, ingress: list[dict[str, Any]] | None = None, egress: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    spec: dict[str, Any] = {"podSelector": selector, "policyTypes": []}
    if ingress is not None:
        spec["ingress"] = ingress
        spec["policyTypes"].append("Ingress")
    if egress is not None:
        spec["egress"] = egress
        spec["policyTypes"].append("Egress")
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": _metadata(profile, name, {"app.kubernetes.io/part-of": "xiaozhi-agent-platform"}), "spec": spec}


def _selector(service: str) -> dict[str, Any]:
    return {"matchLabels": {"app.kubernetes.io/component": service}}


def _namespace_peer(namespace: str) -> dict[str, Any]:
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}}}


def _pod_peer(service: str) -> dict[str, Any]:
    return {"podSelector": {"matchLabels": {"app.kubernetes.io/component": service}}}


def _port(port: int, protocol: str = "TCP") -> dict[str, Any]:
    return {"port": port, "protocol": protocol}


def build_kubernetes_list(profile: dict[str, Any], oci_receipt: dict[str, Any]) -> dict[str, Any]:
    records = {record["name"]: record for record in oci_receipt["services"]}
    items: list[dict[str, Any]] = []
    for service in SERVICES:
        labels = _labels(profile, service)
        name = _resource_name(profile, service)
        items.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": _metadata(profile, name, labels), "automountServiceAccountToken": False})
    for service in SERVICES:
        labels = _labels(profile, service)
        name = _resource_name(profile, service)
        service_spec: dict[str, Any] = {
            "internalTrafficPolicy": "Cluster", "ports": [{"name": "https", "port": PORTS[service], "protocol": "TCP", "targetPort": "https"}],
            "selector": labels, "sessionAffinity": "None", "type": "ClusterIP",
        }
        if service == "generationcoordinator":
            service_spec["clusterIP"] = "None"
        items.append({"apiVersion": "v1", "kind": "Service", "metadata": _metadata(profile, name, labels), "spec": service_spec})
    for service in SERVICES:
        labels = _labels(profile, service)
        name = _resource_name(profile, service)
        digest = records[service]["image_index_digest"]
        image = f"{profile['registry_repository']}/{service}@{digest}"
        template = {"metadata": {"annotations": {"xiaozhi-agent/image-index-digest": digest, "xiaozhi-agent/release-id": oci_receipt["release_id"]}, "labels": labels}, "spec": _pod_spec(profile, service, image)}
        common = {"replicas": 1, "selector": {"matchLabels": labels}, "template": template}
        if service == "generationcoordinator":
            spec = {**common, "podManagementPolicy": "OrderedReady", "serviceName": name, "updateStrategy": {"type": "OnDelete"}}
            kind = "StatefulSet"
        else:
            spec = {**common, "progressDeadlineSeconds": 600, "revisionHistoryLimit": 2, "strategy": {"type": "Recreate"}}
            kind = "Deployment"
        items.append({"apiVersion": "apps/v1", "kind": kind, "metadata": _metadata(profile, name, labels), "spec": spec})
    items.append(_network_policy(profile, f"{profile['deployment_id']}-default-deny-all", {}, ingress=[], egress=[]))
    items.append(_network_policy(profile, f"{profile['deployment_id']}-allow-dns", {}, egress=[{
        "ports": [_port(53, "TCP"), _port(53, "UDP")],
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": profile["dns_namespace"]}}, "podSelector": {"matchLabels": profile["dns_pod_selector"]}}],
    }]))
    for service in PUBLIC_SERVICES:
        items.append(_network_policy(profile, f"{profile['deployment_id']}-{service}-public-ingress", _selector(service), ingress=[{"from": [_namespace_peer(profile["ingress_namespace"])], "ports": [_port(PORTS[service])]}]))
    for service in SERVICES:
        monitor_port = {"accountauthorization": 9080, "factorytimeauthority": 9081}.get(
            service, PORTS[service])
        items.append(_network_policy(profile, f"{profile['deployment_id']}-{service}-monitoring", _selector(service), ingress=[{"from": [_namespace_peer(profile["monitoring_namespace"])], "ports": [_port(monitor_port)]}]))
    items.append(_network_policy(profile, f"{profile['deployment_id']}-generation-internal", _selector("generationcoordinator"), ingress=[{
        "from": [_pod_peer("controlplane"), _pod_peer("firmwareorigin"), _namespace_peer(profile["release_operator_namespace"])], "ports": [_port(8447)],
    }]))
    items.append(_network_policy(
        profile, f"{profile['deployment_id']}-account-internal",
        _selector("accountauthorization"),
        ingress=[{
            "from": [
                _pod_peer("controlplane"),
                _namespace_peer(profile["release_operator_namespace"]),
            ],
            "ports": [_port(9444)],
        }],
    ))
    items.append(_network_policy(
        profile, f"{profile['deployment_id']}-factory-time-station-ingress",
        _selector("factorytimeauthority"),
        ingress=[{"from": [_namespace_peer(profile["ingress_namespace"])],
            "ports": [_port(9445)]}],
    ))
    external_by_service = {
        "gateway": (("speech", 443), ("identity", 443), ("database", 5432)),
        "controlplane": (("identity", 443), ("database", 5432)),
        "agentproxy": (("provider", 443), ("identity", 443), ("database", 5432)),
        "firmwareorigin": (("identity", 443),),
        "generationcoordinator": (),
        "accountauthorization": (("database", 5432),) + (
            (("provider", 443),) if profile["companion_push"]["enabled"] else ()
        ),
        "factorytimeauthority": (("database", 5432), ("signer", 443)),
    }
    internal_by_service = {
        "controlplane": (("generationcoordinator", 8447), ("accountauthorization", 9444)),
        "firmwareorigin": (("generationcoordinator", 8447),),
    }
    for service in SERVICES:
        rules: list[dict[str, Any]] = []
        for dependency, port_number in external_by_service[service]:
            rules.append({"ports": [_port(port_number)], "to": [{"ipBlock": {"cidr": cidr}} for cidr in profile["external_egress"][dependency]]})
        for target, port_number in internal_by_service.get(service, ()):
            rules.append({"ports": [_port(port_number)], "to": [_pod_peer(target)]})
        rules.append({
            "ports": [_port(4318)],
            "to": [{
                "namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": profile["monitoring_namespace"]
                }},
                "podSelector": {"matchLabels": profile["telemetry"]["pod_selector"]},
            }],
        })
        items.append(_network_policy(profile, f"{profile['deployment_id']}-{service}-egress", _selector(service), egress=rules))
    return {"apiVersion": "v1", "items": items, "kind": "List"}


def build_prerequisites(profile: dict[str, Any]) -> dict[str, Any]:
    objects: list[dict[str, Any]] = [{
        "kind": "Namespace", "name": profile["namespace"], "purpose": "workload",
        "required_labels": {
            "pod-security.kubernetes.io/audit": "restricted",
            "pod-security.kubernetes.io/audit-version": "latest",
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "latest",
            "pod-security.kubernetes.io/warn": "restricted",
            "pod-security.kubernetes.io/warn-version": "latest",
            "xiaozhi-agent/deployment-id": profile["deployment_id"],
        },
    }]
    for role in ("ingress", "monitoring", "release_operator", "dns"):
        objects.append({"kind": "Namespace", "name": profile[f"{role}_namespace"], "purpose": role, "required_labels": {"kubernetes.io/metadata.name": profile[f"{role}_namespace"]}})
    objects.append({"immutable_required": True, "kind": "Secret", "name": profile["image_pull_secret"], "namespace": profile["namespace"], "purpose": "registry-auth", "required_keys": [".dockerconfigjson"], "type": "kubernetes.io/dockerconfigjson"})
    for service in SERVICES:
        objects.extend([
            {"immutable_required": True, "kind": "ConfigMap", "name": profile["config_maps"][service], "namespace": profile["namespace"], "purpose": "service-config", "required_keys": list(_config_keys(profile, service)), "service": service},
            {"immutable_required": True, "kind": "Secret", "name": profile["secret_env"][service], "namespace": profile["namespace"], "purpose": "secret-environment", "required_keys": list(SECRET_ENV_KEYS[service]), "service": service, "type": "Opaque"},
            {"immutable_required": True, "kind": "Secret", "name": profile["secret_files"][service], "namespace": profile["namespace"], "purpose": "secret-files", "required_keys": list(_secret_file_keys(profile, service)), "service": service, "type": "Opaque"},
        ])
    for key, services, read_only in (
        ("controlplane_bundle", ["controlplane"], True),
        ("firmwareorigin_bundle", ["firmwareorigin"], True),
        ("generation_state", ["generationcoordinator"], False),
    ):
        objects.append({"kind": "PersistentVolumeClaim", "name": profile["storage_claims"][key], "namespace": profile["namespace"], "purpose": key, "read_only": read_only, "services": services})
    return {"deployment_id": profile["deployment_id"], "namespace": profile["namespace"], "objects": objects, "schema": SCHEMA_VERSION}


def _signature_payload(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("signature_b64url", None)
    return SIGNATURE_DOMAIN + oci._compact_bytes(unsigned)


def build_bundle(*, oci_bundle: Path, oci_trusted_public_key: Path, oci_signing_key_id: str, expected_oci_release_id: str, profile_path: Path, signing_private_key_path: Path, signing_key_id: str, output_path: Path) -> dict[str, Any]:
    if output_path.exists() or output_path.is_symlink():
        raise DeploymentError("output bundle already exists")
    if not output_path.parent.is_dir():
        raise DeploymentError("output bundle parent does not exist")
    profile, profile_data = load_profile(profile_path)
    oci_receipt = oci.validate_release_bundle(oci_bundle, trusted_public_key_path=oci_trusted_public_key, expected_signing_key_id=oci_signing_key_id, expected_release_id=expected_oci_release_id)
    key = oci._load_private_key(signing_private_key_path)
    signing_key_id = oci._require_identifier(signing_key_id, "deployment signing key ID")
    kubernetes_data = oci._json_bytes(build_kubernetes_list(profile, oci_receipt))
    prerequisite_data = oci._json_bytes(build_prerequisites(profile))
    oci_receipt_data = oci._read_regular(oci_bundle / "release-receipt.json", oci.MAX_JSON_BYTES, "OCI release receipt")
    services = [{"image": f"{profile['registry_repository']}/{record['name']}@{record['image_index_digest']}", "image_index_digest": record["image_index_digest"], "name": record["name"]} for record in oci_receipt["services"]]
    receipt: dict[str, Any] = {
        "schema": SCHEMA_VERSION, "deployment_id": profile["deployment_id"],
        "namespace": profile["namespace"], "oci_release_id": oci_receipt["release_id"],
        "oci_receipt_sha256": oci._sha256(oci_receipt_data),
        "oci_signing_key_id": oci_receipt["signing_key_id"],
        "profile_sha256": oci._sha256(profile_data),
        "kubernetes_sha256": oci._sha256(kubernetes_data),
        "prerequisites_sha256": oci._sha256(prerequisite_data),
        "signing_key_id": signing_key_id, "signature_algorithm": "Ed25519",
        "services": services,
    }
    receipt["signature_b64url"] = oci._b64url(key.sign(_signature_payload(receipt)))
    receipt_data = oci._json_bytes(receipt)
    created = False
    try:
        output_path.mkdir(mode=0o700)
        created = True
        oci._write_new(output_path / "profile.json", profile_data)
        oci._write_new(output_path / "kubernetes.json", kubernetes_data)
        oci._write_new(output_path / "prerequisites.json", prerequisite_data)
        oci._write_new(output_path / "deployment-receipt.json", receipt_data)
        oci._write_new(output_path / "READY", (oci._sha256(receipt_data) + "\n").encode("ascii"))
        oci._fsync_directory(output_path)
        oci._lock_tree(output_path)
    except BaseException:
        if created:
            oci._unlock_tree(output_path)
            shutil.rmtree(output_path)
        raise
    return receipt


def validate_bundle(root: Path, *, oci_bundle: Path, oci_trusted_public_key: Path, expected_oci_signing_key_id: str, expected_oci_release_id: str, trusted_public_key: Path, expected_signing_key_id: str, expected_deployment_id: str) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise DeploymentError("deployment bundle must be a non-symlink directory")
    expected_files = {"READY", "deployment-receipt.json", "kubernetes.json", "prerequisites.json", "profile.json"}
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise DeploymentError("deployment bundle contains a non-regular object")
        if path.stat().st_mode & 0o222:
            raise DeploymentError("deployment bundle must be read-only")
        if path.is_file():
            actual_files.add(path.relative_to(root).as_posix())
    if root.stat().st_mode & 0o222 or actual_files != expected_files:
        raise DeploymentError("deployment bundle layout or permissions are invalid")
    receipt_data = oci._read_regular(root / "deployment-receipt.json", oci.MAX_JSON_BYTES, "deployment receipt")
    receipt = oci._strict_json(receipt_data, "deployment receipt")
    if not isinstance(receipt, dict) or oci._json_bytes(receipt) != receipt_data:
        raise DeploymentError("deployment receipt is not canonical JSON")
    fields = {"schema", "deployment_id", "namespace", "oci_release_id", "oci_receipt_sha256", "oci_signing_key_id", "profile_sha256", "kubernetes_sha256", "prerequisites_sha256", "signing_key_id", "signature_algorithm", "signature_b64url", "services"}
    if set(receipt) != fields or receipt.get("schema") != SCHEMA_VERSION or receipt.get("signature_algorithm") != "Ed25519":
        raise DeploymentError("deployment receipt fields or schema are invalid")
    if receipt.get("deployment_id") != expected_deployment_id or receipt.get("signing_key_id") != expected_signing_key_id:
        raise DeploymentError("deployment receipt does not match external trust policy")
    signature = oci._decode_b64url(receipt.get("signature_b64url"), 64, "deployment signature")
    public_key = oci._load_public_key(trusted_public_key)
    try:
        public_key.verify(signature, _signature_payload(receipt))
    except InvalidSignature as error:
        raise DeploymentError("deployment receipt signature is invalid") from error
    ready = oci._read_regular(root / "READY", 128, "deployment READY")
    if ready != (oci._sha256(receipt_data) + "\n").encode("ascii"):
        raise DeploymentError("deployment READY marker is invalid")
    profile, profile_data = load_profile(root / "profile.json")
    kubernetes_data = oci._read_regular(root / "kubernetes.json", oci.MAX_JSON_BYTES, "Kubernetes resources")
    prerequisite_data = oci._read_regular(root / "prerequisites.json", oci.MAX_JSON_BYTES, "deployment prerequisites")
    if receipt.get("profile_sha256") != oci._sha256(profile_data) or receipt.get("kubernetes_sha256") != oci._sha256(kubernetes_data) or receipt.get("prerequisites_sha256") != oci._sha256(prerequisite_data):
        raise DeploymentError("deployment content does not match receipt")
    oci_receipt = oci.validate_release_bundle(oci_bundle, trusted_public_key_path=oci_trusted_public_key, expected_signing_key_id=expected_oci_signing_key_id, expected_release_id=expected_oci_release_id)
    oci_receipt_data = oci._read_regular(oci_bundle / "release-receipt.json", oci.MAX_JSON_BYTES, "OCI release receipt")
    if receipt.get("oci_release_id") != oci_receipt["release_id"] or receipt.get("oci_signing_key_id") != oci_receipt["signing_key_id"] or receipt.get("oci_receipt_sha256") != oci._sha256(oci_receipt_data):
        raise DeploymentError("deployment is not bound to the trusted OCI release")
    expected_services = [{"image": f"{profile['registry_repository']}/{record['name']}@{record['image_index_digest']}", "image_index_digest": record["image_index_digest"], "name": record["name"]} for record in oci_receipt["services"]]
    if receipt.get("services") != expected_services:
        raise DeploymentError("deployment service images do not match the OCI receipt")
    if kubernetes_data != oci._json_bytes(build_kubernetes_list(profile, oci_receipt)):
        raise DeploymentError("Kubernetes resources violate the deterministic hardened contract")
    if prerequisite_data != oci._json_bytes(build_prerequisites(profile)):
        raise DeploymentError("deployment prerequisites violate the isolation contract")
    return receipt
