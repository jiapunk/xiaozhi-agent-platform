#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$#" -ne 1 ]; then
    echo "usage: FIRMWARE_SBOM_TOOL=/absolute/path/to/esp-idf-sbom $0 OUTPUT_DIR" >&2
    exit 2
fi
if [ -z "${FIRMWARE_SBOM_TOOL:-}" ]; then
    echo "FIRMWARE_SBOM_TOOL must name the pinned esp-idf-sbom 1.2.0 executable" >&2
    exit 2
fi

output_dir=$1

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/build_firmware_sbom_bundle.py" \
    --project-description \
    "$project_dir/build-box3-production-security/project_description.json" \
    --policy "$project_dir/firmware/sbom-release-policy.json" \
    --sbom-tool "$FIRMWARE_SBOM_TOOL" \
    --output-dir "$output_dir"

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/verify_firmware_sbom_bundle.py" \
    --bundle "$output_dir" \
    --project-description \
    "$project_dir/build-box3-production-security/project_description.json" \
    --policy "$project_dir/firmware/sbom-release-policy.json"

echo "BOX3 firmware SBOM release gate PASS; preserve the immutable bundle with the signed firmware release"
