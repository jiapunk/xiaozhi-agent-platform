#!/usr/bin/env python3
"""Validate one externally signed, content-free backend SLO observation."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import pathlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature

import oci_release as oci


SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-BACKEND-SLO-OBSERVATION-V1\x00"
SERVICES = (
    "gateway", "controlplane", "agentproxy", "firmwareorigin",
    "generationcoordinator", "accountauthorization", "factorytimeauthority",
)
IDENTIFIER = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,62}[a-z0-9])?$")
OBSERVATION_FIELDS = {
    "schema", "observation_id", "deployment_id", "collector_id",
    "policy_sha256", "window_start", "window_end", "generated_at",
    "services", "result", "signing_key_id", "signature_algorithm",
    "signature_b64url",
}
SERVICE_FIELDS = {
    "name", "eligible_requests", "successes", "server_errors",
    "availability_ppm", "latency_p99_ms", "telemetry_export_failures",
    "unknown_operations", "attribute_violations", "result",
}


class SLOError(ValueError):
    pass


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise SLOError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise SLOError(f"{label} is invalid")
    return value


def _timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise SLOError(f"{label} is not a canonical UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as error:
        raise SLOError(f"{label} is not a canonical UTC timestamp") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise SLOError(f"{label} is not a canonical UTC timestamp")
    return parsed


def load_policy(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    try:
        data = oci._read_regular(path, oci.MAX_JSON_BYTES, "backend SLO policy")
        value = oci._strict_json(data, "backend SLO policy")
    except (OSError, oci.OCIReleaseError) as error:
        raise SLOError("backend SLO policy is unreadable") from error
    if oci._json_bytes(value) != data or not isinstance(value, dict) or set(value) != {
        "schema", "window_seconds", "maximum_observation_age_seconds",
        "eligible_result_classes", "attribute_policy", "services",
    } or value.get("schema") != 1:
        raise SLOError("backend SLO policy is noncanonical or incomplete")
    if value.get("window_seconds") != 2_419_200 or \
            _integer(value.get("maximum_observation_age_seconds"), 3600, 604800,
                     "maximum observation age") < 3600 or \
            value.get("eligible_result_classes") != ["server_error", "success"]:
        raise SLOError("backend SLO evaluation window is invalid")
    expected_attributes = {
        "allowed_span_attributes": [
            "http.request.method", "http.response.status_code",
            "xiaozhi.operation", "xiaozhi.result_class",
        ],
        "forbidden_propagation_headers": ["baggage", "tracestate"],
        "internal_context_services": [
            "accountauthorization", "generationcoordinator",
        ],
        "public_edge_services": [
            "agentproxy", "controlplane", "factorytimeauthority",
            "firmwareorigin", "gateway",
        ],
        "third_party_no_context_operations": [
            "agent.provider", "push.apns", "push.fcm", "push.oauth",
        ],
    }
    if value.get("attribute_policy") != expected_attributes:
        raise SLOError("backend SLO content policy is invalid")
    services = value.get("services")
    if not isinstance(services, list) or len(services) != len(SERVICES):
        raise SLOError("backend SLO service inventory is invalid")
    for expected, service in zip(SERVICES, services):
        if not isinstance(service, dict) or set(service) != {
            "name", "availability_target_ppm", "latency_p99_ms",
            "minimum_eligible_requests",
        } or service.get("name") != expected:
            raise SLOError("backend SLO service order or fields are invalid")
        _integer(service.get("availability_target_ppm"), 900000, 1_000_000,
                 f"{expected} availability target")
        _integer(service.get("latency_p99_ms"), 1, 120000,
                 f"{expected} latency target")
        _integer(service.get("minimum_eligible_requests"), 100, 10_000_000,
                 f"{expected} minimum request count")
    return value, data


def signature_payload(observation: dict[str, Any]) -> bytes:
    unsigned = dict(observation)
    unsigned.pop("signature_b64url", None)
    return SIGNATURE_DOMAIN + oci._compact_bytes(unsigned)


def validate_observation(
    observation_path: pathlib.Path,
    policy_path: pathlib.Path,
    trusted_public_key_path: pathlib.Path,
    *,
    expected_signing_key_id: str,
    expected_deployment_id: str,
    expected_collector_id: str,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    policy, policy_data = load_policy(policy_path)
    for value, label in (
        (expected_signing_key_id, "expected signing key ID"),
        (expected_deployment_id, "expected deployment ID"),
        (expected_collector_id, "expected collector ID"),
    ):
        _identifier(value, label)
    try:
        data = oci._read_regular(
            observation_path, oci.MAX_JSON_BYTES, "backend SLO observation"
        )
        value = oci._strict_json(data, "backend SLO observation")
    except (OSError, oci.OCIReleaseError) as error:
        raise SLOError("backend SLO observation is unreadable") from error
    if oci._json_bytes(value) != data or not isinstance(value, dict) or \
            set(value) != OBSERVATION_FIELDS or value.get("schema") != 1:
        raise SLOError("backend SLO observation is noncanonical or incomplete")
    _identifier(value.get("observation_id"), "observation ID")
    if value.get("deployment_id") != expected_deployment_id or \
            value.get("collector_id") != expected_collector_id or \
            value.get("signing_key_id") != expected_signing_key_id or \
            value.get("signature_algorithm") != "Ed25519" or \
            value.get("result") != "PASS":
        raise SLOError("backend SLO observation identity or result differs")
    expected_policy_digest = hashlib.sha256(policy_data).hexdigest()
    if value.get("policy_sha256") != expected_policy_digest:
        raise SLOError("backend SLO observation policy digest differs")
    try:
        signature = oci._decode_b64url(
            value.get("signature_b64url"), 64, "backend SLO signature"
        )
        public_key = oci._load_public_key(trusted_public_key_path)
        public_key.verify(signature, signature_payload(value))
    except (InvalidSignature, oci.OCIReleaseError, OSError) as error:
        raise SLOError("backend SLO observation signature is invalid") from error
    window_start = _timestamp(value.get("window_start"), "window start")
    window_end = _timestamp(value.get("window_end"), "window end")
    generated_at = _timestamp(value.get("generated_at"), "generated at")
    if int((window_end - window_start).total_seconds()) != policy["window_seconds"] or \
            generated_at < window_end or generated_at > window_end + dt.timedelta(hours=1):
        raise SLOError("backend SLO observation window is invalid")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise SLOError("validation time must be timezone aware")
    current = current.astimezone(dt.timezone.utc)
    if generated_at > current + dt.timedelta(minutes=5) or \
            current - generated_at > dt.timedelta(
                seconds=policy["maximum_observation_age_seconds"]
            ):
        raise SLOError("backend SLO observation is stale or from the future")
    services = value.get("services")
    if not isinstance(services, list) or len(services) != len(SERVICES):
        raise SLOError("backend SLO observation service inventory is invalid")
    for expected, target, observed in zip(
        SERVICES, policy["services"], services
    ):
        if not isinstance(observed, dict) or set(observed) != SERVICE_FIELDS or \
                observed.get("name") != expected or observed.get("result") != "PASS":
            raise SLOError(f"{expected} SLO observation fields differ")
        eligible = _integer(observed.get("eligible_requests"), 1, 10**15,
                            f"{expected} eligible requests")
        successes = _integer(observed.get("successes"), 0, eligible,
                             f"{expected} successes")
        errors = _integer(observed.get("server_errors"), 0, eligible,
                          f"{expected} server errors")
        availability = _integer(observed.get("availability_ppm"), 0, 1_000_000,
                                f"{expected} availability")
        latency = _integer(observed.get("latency_p99_ms"), 0, 120000,
                           f"{expected} latency")
        if successes + errors != eligible or \
                availability != successes * 1_000_000 // eligible:
            raise SLOError(f"{expected} SLO arithmetic differs")
        if eligible < target["minimum_eligible_requests"] or \
                availability < target["availability_target_ppm"] or \
                latency > target["latency_p99_ms"]:
            raise SLOError(f"{expected} production SLO failed")
        for field in (
            "telemetry_export_failures", "unknown_operations",
            "attribute_violations",
        ):
            if _integer(observed.get(field), 0, 10**15,
                        f"{expected} {field}") != 0:
                raise SLOError(f"{expected} telemetry completeness failed")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation", required=True, type=pathlib.Path)
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    parser.add_argument("--trusted-public-key", required=True, type=pathlib.Path)
    parser.add_argument("--expected-signing-key-id", required=True)
    parser.add_argument("--expected-deployment-id", required=True)
    parser.add_argument("--expected-collector-id", required=True)
    arguments = parser.parse_args()
    try:
        validate_observation(
            arguments.observation, arguments.policy, arguments.trusted_public_key,
            expected_signing_key_id=arguments.expected_signing_key_id,
            expected_deployment_id=arguments.expected_deployment_id,
            expected_collector_id=arguments.expected_collector_id,
        )
    except SLOError as error:
        parser.error(str(error))
    print("backend SLO observation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
