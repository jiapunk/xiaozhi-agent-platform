#!/usr/bin/env python3
"""Canonical, fail-closed product launch-lane decision validator."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import re
import stat
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
MAX_BYTES = 32 * 1024
MAX_APPROVAL_SECONDS = 180 * 24 * 60 * 60
MAX_POLICY_REVIEW_AGE_DAYS = 30
MAX_UNIX_SECONDS = 4_102_444_800  # 2100-01-01T00:00:00Z
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SKU = re.compile(r"^[A-Z0-9][A-Z0-9_.-]{0,63}$")
MARKET = re.compile(r"^[A-Z]{2}$")
SENTINEL = "UNSELECTED"
RESERVED_PARTS = {"demo", "example", "fixture", "local", "mock", "test", "tbd", "unselected"}

FIELDS = {
    "schema_version", "decision_id", "revision", "status", "sku",
    "customer_lane", "target_markets", "sales_channel",
    "ios_distribution", "android_distribution", "entitlement_source",
    "billing_provider_id", "identity_provider_id", "sdk_distribution_id",
    "legal_review_id", "decision_owner_id", "policy_reviewed_on",
    "approved_at_unix", "expires_at_unix",
}
LANES = {
    "developer_system_integrator",
    "direct_consumer_hardware_cloud",
    "consumer_mobile_subscription",
}
SALES_CHANNELS = {
    "undecided", "direct_contract_invoice", "direct_web_checkout",
    "apple_google_in_app", "mixed_region_specific",
}
IOS_DISTRIBUTIONS = {
    "undecided", "business_custom", "public_free_companion",
    "public_iap", "unlisted", "not_offered",
}
ANDROID_DISTRIBUTIONS = {
    "undecided", "managed_custom", "public_consumption_only",
    "public_play_billing", "direct_distribution", "not_offered",
}
ENTITLEMENT_SOURCES = {
    "undecided", "contract_invoice_adapter", "web_billing_adapter",
    "apple_google_billing_adapters", "multi_provider_adapters",
}


class LaunchDecisionError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise LaunchDecisionError("launch decision contains duplicate fields")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise LaunchDecisionError(
            f"launch decision contains non-standard constant {value}")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaunchDecisionError(
            "launch decision is not strict UTF-8 JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise LaunchDecisionError("launch decision is not canonical JSON")
    return value


def _read_regular(path: pathlib.Path) -> bytes:
    absolute = pathlib.Path(os.path.abspath(path))
    try:
        before = absolute.lstat()
    except OSError as error:
        raise LaunchDecisionError("launch decision cannot be opened") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_BYTES:
        raise LaunchDecisionError("launch decision must be a bounded regular non-symlink file")
    try:
        with absolute.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if not os.path.samestat(before, opened):
                raise LaunchDecisionError("launch decision changed while opening")
            raw = handle.read(MAX_BYTES + 1)
    except OSError as error:
        raise LaunchDecisionError("launch decision cannot be read") from error
    if len(raw) != before.st_size or len(raw) > MAX_BYTES:
        raise LaunchDecisionError("launch decision size changed while reading")
    return raw


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str]) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise LaunchDecisionError(
            f"launch decision fields mismatch; missing={sorted(wanted - actual)}, "
            f"unexpected={sorted(actual - wanted)}")


def _valid_identifier(value: Any, *, approved: bool) -> bool:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        return False
    if not approved:
        return True
    parts = {part.lower() for part in re.split(r"[_.:-]+", value)}
    return value != SENTINEL and parts.isdisjoint(RESERVED_PARTS)


def _valid_review_date(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        return False
    try:
        return datetime.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def validate(value: Mapping[str, Any], *, require_approved: bool = False) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LaunchDecisionError("launch decision must be an object")
    _exact_keys(value, FIELDS)
    status = value["status"]
    if status not in {"PROPOSED", "APPROVED"}:
        raise LaunchDecisionError("launch decision status is invalid")
    approved = status == "APPROVED"
    if require_approved and not approved:
        raise LaunchDecisionError("product launch decision is not APPROVED")
    if value["schema_version"] != SCHEMA_VERSION or isinstance(value["revision"], bool) or not isinstance(value["revision"], int) or not 1 <= value["revision"] <= (1 << 32) - 1:
        raise LaunchDecisionError("launch decision version or revision is invalid")
    if not _valid_identifier(value["decision_id"], approved=approved):
        raise LaunchDecisionError("launch decision ID is invalid")
    if not isinstance(value["sku"], str) or not SKU.fullmatch(value["sku"]):
        raise LaunchDecisionError("launch SKU is invalid")
    if value["customer_lane"] not in LANES:
        raise LaunchDecisionError("customer lane is invalid")
    markets = value["target_markets"]
    if not isinstance(markets, list) or any(
            not isinstance(item, str) or not MARKET.fullmatch(item)
            for item in markets) or markets != sorted(set(markets)):
        raise LaunchDecisionError(
            "target markets must be sorted unique uppercase alpha-2-shaped codes")
    if approved and not 1 <= len(markets) <= 8:
        raise LaunchDecisionError("approved launch requires one to eight target markets")
    if value["sales_channel"] not in SALES_CHANNELS or value["ios_distribution"] not in IOS_DISTRIBUTIONS or value["android_distribution"] not in ANDROID_DISTRIBUTIONS or value["entitlement_source"] not in ENTITLEMENT_SOURCES:
        raise LaunchDecisionError("launch channel or distribution is invalid")
    for field in (
        "billing_provider_id", "identity_provider_id", "sdk_distribution_id",
        "legal_review_id", "decision_owner_id",
    ):
        if not _valid_identifier(value[field], approved=approved):
            raise LaunchDecisionError(f"{field} is invalid")
    if not _valid_review_date(value["policy_reviewed_on"]):
        raise LaunchDecisionError("policy review date is invalid")
    approved_at = value["approved_at_unix"]
    expires_at = value["expires_at_unix"]
    if isinstance(approved_at, bool) or isinstance(expires_at, bool) or not isinstance(approved_at, int) or not isinstance(expires_at, int):
        raise LaunchDecisionError("approval times must be integers")
    if approved:
        if approved_at <= 0 or expires_at <= approved_at or expires_at > MAX_UNIX_SECONDS or expires_at - approved_at > MAX_APPROVAL_SECONDS:
            raise LaunchDecisionError("approved launch decision validity is invalid")
        approval_date = datetime.datetime.fromtimestamp(
            approved_at, tz=datetime.timezone.utc).date()
        review_date = datetime.date.fromisoformat(value["policy_reviewed_on"])
        if review_date > approval_date or (
                approval_date - review_date).days > MAX_POLICY_REVIEW_AGE_DAYS:
            raise LaunchDecisionError(
                "approved launch policy review is stale or after approval")
    elif approved_at != 0 or expires_at != 0:
        raise LaunchDecisionError("proposed launch decision cannot carry approval times")
    _validate_lane(value, approved=approved)
    return dict(value)


def _validate_lane(value: Mapping[str, Any], *, approved: bool) -> None:
    lane = value["customer_lane"]
    sales = value["sales_channel"]
    ios = value["ios_distribution"]
    android = value["android_distribution"]
    entitlement = value["entitlement_source"]
    paths = {sales, ios, android, entitlement}
    if approved and "undecided" in paths:
        raise LaunchDecisionError("approved launch cannot contain undecided channels")
    if approved and ios == "not_offered" and android == "not_offered":
        raise LaunchDecisionError("approved launch must offer at least one companion platform")
    if lane == "developer_system_integrator":
        if (
                sales not in {"undecided", "direct_contract_invoice"} or
                entitlement not in {"undecided", "contract_invoice_adapter"} or
                ios == "public_iap" or android == "public_play_billing"):
            raise LaunchDecisionError("developer/system-integrator lane contract is inconsistent")
    elif lane == "direct_consumer_hardware_cloud":
        if (
                sales not in {
                    "undecided", "direct_web_checkout", "mixed_region_specific"} or
                entitlement not in {
                    "undecided", "web_billing_adapter", "multi_provider_adapters"} or
                ios not in {
                    "undecided", "public_free_companion", "public_iap",
                    "unlisted", "not_offered"} or
                android not in {
                    "undecided", "public_consumption_only", "public_play_billing",
                    "direct_distribution", "not_offered"}):
            raise LaunchDecisionError(
                "direct-consumer hardware/cloud lane contract is inconsistent")
        if sales == "direct_web_checkout" and (
                ios == "public_iap" or android == "public_play_billing"):
            raise LaunchDecisionError(
                "direct web checkout cannot claim in-app billing distribution")
    elif lane == "consumer_mobile_subscription":
        if (
                sales not in {
                    "undecided", "apple_google_in_app", "mixed_region_specific"} or
                ios not in {"undecided", "public_iap", "not_offered"} or
                android not in {
                    "undecided", "public_play_billing", "not_offered"} or
                entitlement not in {
                    "undecided", "apple_google_billing_adapters",
                    "multi_provider_adapters"}):
            raise LaunchDecisionError("consumer mobile subscription lane contract is inconsistent")


def load(path: pathlib.Path, *, require_approved: bool = False) -> dict[str, Any]:
    return validate(_strict_json(_read_regular(path)),
                    require_approved=require_approved)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision", required=True, type=pathlib.Path)
    parser.add_argument("--require-approved", action="store_true")
    args = parser.parse_args()
    try:
        value = load(args.decision, require_approved=args.require_approved)
    except LaunchDecisionError as error:
        parser.error(str(error))
    print(f"PRODUCT_LAUNCH_DECISION_{value['status']}_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
