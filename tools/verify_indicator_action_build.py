#!/usr/bin/env python3
"""Verify the BOX-3 indicator action's config and final ELF boundary."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


CONFIG_NAME = "CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE"
REQUIRED_ENABLED_SYMBOLS = {
    "product_agent_set_indicator",
    "product_status_indicator_create",
    "product_status_indicator_destroy",
    "product_status_indicator_get",
    "product_status_indicator_set",
}
FORBIDDEN_DISABLED_PREFIXES = (
    "product_agent_set_indicator",
    "product_status_indicator_",
)


class VerificationError(ValueError):
    pass


def parse_enabled(config_text: str) -> bool:
    enabled = f"{CONFIG_NAME}=y"
    disabled = f"# {CONFIG_NAME} is not set"
    matches = [
        line.strip()
        for line in config_text.splitlines()
        if line.strip().startswith(CONFIG_NAME)
        or line.strip().startswith(f"# {CONFIG_NAME}")
    ]
    if matches == [enabled]:
        return True
    if matches == [disabled]:
        return False
    raise VerificationError(
        f"{CONFIG_NAME} must occur exactly once as enabled or explicitly disabled"
    )


def parse_defined_symbols(nm_output: str) -> set[str]:
    symbols: set[str] = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            symbols.add(fields[-1])
    return symbols


def verify_boundary(*, enabled: bool, symbols: set[str], expect: str) -> None:
    if expect == "enabled":
        if not enabled:
            raise VerificationError("development indicator action is not enabled")
        missing = REQUIRED_ENABLED_SYMBOLS - symbols
        if missing:
            raise VerificationError(
                "development ELF is missing indicator symbols: "
                + ", ".join(sorted(missing))
            )
        return

    if enabled:
        raise VerificationError("production indicator action is enabled")
    leaked = sorted(
        symbol
        for symbol in symbols
        if symbol.startswith(FORBIDDEN_DISABLED_PREFIXES)
    )
    if leaked:
        raise VerificationError(
            "production ELF contains indicator symbols: " + ", ".join(leaked)
        )


def read_symbols(nm: str, elf: Path) -> set[str]:
    result = subprocess.run(
        [nm, "--defined-only", str(elf)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "nm failed without diagnostic output"
        raise VerificationError(detail)
    return parse_defined_symbols(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdkconfig", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--expect", choices=("enabled", "disabled"), required=True)
    parser.add_argument("--nm", default="xtensa-esp32s3-elf-nm")
    args = parser.parse_args()
    try:
        enabled = parse_enabled(args.sdkconfig.read_text(encoding="utf-8"))
        symbols = read_symbols(args.nm, args.elf)
        verify_boundary(enabled=enabled, symbols=symbols, expect=args.expect)
    except (OSError, subprocess.SubprocessError, VerificationError) as error:
        print(f"indicator action build verification FAILED: {error}", file=sys.stderr)
        return 1
    print(
        f"indicator action build verification PASS: {args.expect} config and ELF"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
