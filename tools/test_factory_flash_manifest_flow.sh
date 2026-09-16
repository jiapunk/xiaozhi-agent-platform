#!/usr/bin/env sh
set -eu
umask 077
if [ "${XZ_FACTORY_TRACE:-0}" = "1" ]; then
    set -x
fi

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir=${1:?build directory is required}
product_signed_bootloader=${2:?signed bootloader is required}
product_signed_application=${3:?signed application is required}
product_signed_receipt=${4:?signed-artifact receipt is required}

if [ -z "${IDF_PATH:-}" ] || [ ! -d "$IDF_PATH" ]; then
    echo "IDF_PATH is required for the frozen NVS tools" >&2
    exit 1
fi
if ! command -v python >/dev/null 2>&1 ||
   ! python -c 'import espsecure' >/dev/null 2>&1; then
    echo "ESP-IDF espsecure Python environment is unavailable" >&2
    exit 1
fi

product_nvs_generator="$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py"
product_nvs_tool="$IDF_PATH/components/nvs_flash/nvs_partition_tool/nvs_tool.py"
if [ ! -f "$product_nvs_generator" ] || [ ! -f "$product_nvs_tool" ]; then
    echo "frozen ESP-IDF NVS tools are unavailable" >&2
    exit 1
fi

product_temp_dir=$(mktemp -d /tmp/xz-factory-flash.XXXXXX)
case "$product_temp_dir" in
    /tmp/xz-factory-flash.*) ;;
    *) echo "unexpected factory flash test directory" >&2; exit 1 ;;
esac

product_flash_key="$product_temp_dir/flash-key.bin"
product_identity_key="$product_temp_dir/identity-key.bin"
product_sku_manifest="$product_temp_dir/sku-manifest.bin"
product_sku_evidence="$product_temp_dir/sku-evidence.json"
product_material="$product_temp_dir/material.bin"
product_nvs_csv="$product_temp_dir/nvs.csv"
product_label="$product_temp_dir/label.json"
product_nvs_image="$product_temp_dir/nvs-factory.bin"
product_manifest="$product_temp_dir/encrypted-flash-manifest.json"
product_observation_public_key="$product_temp_dir/observation-public.pem"
product_observation_request="$product_temp_dir/observation-request.json"
product_observation_signature="$product_temp_dir/observation-signature.bin"
product_observation_receipt="$product_temp_dir/observation-receipt.json"

product_cleanup() {
    if [ -d "$product_temp_dir" ]; then
        find "$product_temp_dir" -type f -exec unlink {} \;
        rmdir "$product_temp_dir" 2>/dev/null || true
    fi
}
trap product_cleanup EXIT HUP INT TERM

python -m espsecure generate-flash-encryption-key "$product_flash_key" >/dev/null
python3 "$product_project_dir/tools/generate_factory_hmac_key.py" \
    --purpose identity --output "$product_identity_key" >/dev/null
python3 "$product_project_dir/tools/generate_factory_sku_manifest.py" \
    --device-hmac-key "$product_identity_key" \
    --base-mac 02:00:00:00:00:01 \
    --sku VOICE_AGENT_KIT_BOX3 \
    --board esp32s3-box3 \
    --hardware-revision 1 \
    --chip-revision 1 \
    --factory-record-version 7 \
    --manifest-id 00112233445566778899aabbccddeeff \
    --manifest-output "$product_sku_manifest" \
    --evidence-output "$product_sku_evidence" >/dev/null
python3 "$product_project_dir/tools/generate_onboarding_bundle.py" \
    --device-hmac-key "$product_identity_key" \
    --mac 02:00:00:00:00:02 \
    --username xiaozhi \
    --sku-manifest "$product_sku_manifest" \
    --material-output "$product_material" \
    --nvs-csv-output "$product_nvs_csv" \
    --label-output "$product_label" >/dev/null
python "$product_nvs_generator" generate --version 2 \
    "$product_nvs_csv" "$product_nvs_image" 0x6000 >/dev/null

python -m espsecure encrypt-flash-data --aes-xts \
    --keyfile "$product_flash_key" --address 0x0 \
    --output "$product_temp_dir/bootloader-encrypted.bin" \
    "$product_signed_bootloader" >/dev/null
python -m espsecure encrypt-flash-data --aes-xts \
    --keyfile "$product_flash_key" --address 0x10000 \
    --output "$product_temp_dir/partition-table-encrypted.bin" \
    "$product_build_dir/partition_table/partition-table.bin" >/dev/null
python -m espsecure encrypt-flash-data --aes-xts \
    --keyfile "$product_flash_key" --address 0x21000 \
    --output "$product_temp_dir/ota-data-encrypted.bin" \
    "$product_build_dir/ota_data_initial.bin" >/dev/null
python -m espsecure encrypt-flash-data --aes-xts \
    --keyfile "$product_flash_key" --address 0x40000 \
    --output "$product_temp_dir/application-encrypted.bin" \
    "$product_signed_application" >/dev/null

cp "$product_temp_dir/bootloader-encrypted.bin" "$product_temp_dir/bootloader-readback.bin"
cp "$product_temp_dir/partition-table-encrypted.bin" "$product_temp_dir/partition-table-readback.bin"
cp "$product_nvs_image" "$product_temp_dir/nvs-factory-readback.bin"
cp "$product_temp_dir/ota-data-encrypted.bin" "$product_temp_dir/ota-data-readback.bin"
cp "$product_temp_dir/application-encrypted.bin" "$product_temp_dir/application-readback.bin"

printf '%s\n' "fixture calibration test fixture only" >"$product_temp_dir/fixture-calibration.txt"
printf '%s\n' "synthetic port fingerprint test fixture only" >"$product_temp_dir/port-fingerprint.txt"
printf '%s\n' "synthetic ESP32-S3 chip probe test fixture only" >"$product_temp_dir/chip-probe.log"
printf '%s\n' \
    "espefuse v5.3.1" \
    "MAC (BLOCK1) MAC address" \
    " = 02:00:00:00:00:01 (OK) R/W" \
    "DIS_DOWNLOAD_MODE (BLOCK0) download mode = False R/W (0b0)" \
    "DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0) manual encrypt = True R/W (0b1)" \
    "SPI_BOOT_CRYPT_CNT (BLOCK0) flash encryption = Enable R/W (0b111)" \
    "SECURE_BOOT_EN (BLOCK0) secure boot = True R/W (0b1)" \
    "ENABLE_SECURITY_DOWNLOAD (BLOCK0) secure download = False R/W (0b0)" \
    "SECURE_VERSION (BLOCK0) anti rollback = 1 R/W (0x0001)" \
    >"$product_temp_dir/efuse-before.txt"
cp "$product_temp_dir/efuse-before.txt" "$product_temp_dir/efuse-after.txt"

product_signing_request_sha=$(shasum -a 256 "$product_build_dir/production-security-signing-request.json" | awk '{print $1}')
product_signed_receipt_sha=$(shasum -a 256 "$product_signed_receipt" | awk '{print $1}')
python3 "$product_project_dir/tools/build_factory_physical_observation_request.py" \
    --observation-id physical-readback-test-0001 \
    --transaction-id factory-test-tx-0001 \
    --attempt-id factory-test-attempt-0001 \
    --device-id xz-020000000001 \
    --serial-number TEST-SN-0001 \
    --base-mac 02:00:00:00:00:01 \
    --chip-revision 1 \
    --signing-request-sha256 "$product_signing_request_sha" \
    --signed-artifact-verification-sha256 "$product_signed_receipt_sha" \
    --anti-rollback-secure-version 1 \
    --station-id ephemeral-contract-test-station \
    --operator test-operator-a \
    --operator test-operator-b \
    --fixture-id synthetic-contract-fixture \
    --fixture-version 1.0.0 \
    --fixture-calibration "$product_temp_dir/fixture-calibration.txt" \
    --signing-key-id ephemeral-untrusted-contract-key \
    --port-fingerprint "$product_temp_dir/port-fingerprint.txt" \
    --chip-probe-log "$product_temp_dir/chip-probe.log" \
    --efuse-summary-before "$product_temp_dir/efuse-before.txt" \
    --efuse-summary-after "$product_temp_dir/efuse-after.txt" \
    --readback-bootloader "$product_temp_dir/bootloader-readback.bin" \
    --readback-partition-table "$product_temp_dir/partition-table-readback.bin" \
    --readback-nvs-factory "$product_temp_dir/nvs-factory-readback.bin" \
    --readback-ota-data-initial "$product_temp_dir/ota-data-readback.bin" \
    --readback-application "$product_temp_dir/application-readback.bin" \
    --started-at 2026-08-10T10:00:00Z \
    --finished-at 2026-08-10T10:05:00Z \
    --output "$product_observation_request" >/dev/null
python3 "$product_project_dir/tools/tests/sign_factory_physical_observation_fixture.py" \
    --request "$product_observation_request" \
    --signature-output "$product_observation_signature" \
    --public-key-output "$product_observation_public_key" >/dev/null
python3 "$product_project_dir/tools/finalize_factory_physical_observation.py" \
    --request "$product_observation_request" \
    --signature "$product_observation_signature" \
    --public-key "$product_observation_public_key" \
    --output "$product_observation_receipt" >/dev/null
python3 "$product_project_dir/tools/verify_factory_physical_observation.py" \
    --receipt "$product_observation_receipt" \
    --public-key "$product_observation_public_key" >/dev/null

product_build_manifest() {
    python3 "$product_project_dir/tools/build_factory_flash_manifest.py" \
        --transaction-id factory-test-tx-0001 \
        --attempt-id factory-test-attempt-0001 \
        --device-id xz-020000000001 \
        --serial-number TEST-SN-0001 \
        --base-mac "$1" \
        --chip-revision 1 \
        --signing-request "$product_build_dir/production-security-signing-request.json" \
        --signed-artifact-verification "$product_signed_receipt" \
        --signed-bootloader "$product_signed_bootloader" \
        --signed-application "$product_signed_application" \
        --partition-table "$product_build_dir/partition_table/partition-table.bin" \
        --ota-data-initial "$product_build_dir/ota_data_initial.bin" \
        --factory-sku-manifest "$product_sku_manifest" \
        --factory-sku-evidence "$product_sku_evidence" \
        --onboarding-material "$product_material" \
        --nvs-csv "$product_nvs_csv" \
        --nvs-factory-image "$product_nvs_image" \
        --encrypted-bootloader "$product_temp_dir/bootloader-encrypted.bin" \
        --encrypted-partition-table "$product_temp_dir/partition-table-encrypted.bin" \
        --encrypted-ota-data-initial "$product_temp_dir/ota-data-encrypted.bin" \
        --encrypted-application "$product_temp_dir/application-encrypted.bin" \
        --readback-bootloader "$product_temp_dir/bootloader-readback.bin" \
        --readback-partition-table "$product_temp_dir/partition-table-readback.bin" \
        --readback-nvs-factory "$product_temp_dir/nvs-factory-readback.bin" \
        --readback-ota-data-initial "$product_temp_dir/ota-data-readback.bin" \
        --readback-application "$product_temp_dir/application-readback.bin" \
        --physical-observation "$product_observation_receipt" \
        --physical-observation-public-key "$product_observation_public_key" \
        --flash-encryption-key "$product_flash_key" \
        --espsecure-python "$(command -v python)" \
        --nvs-tool "$product_nvs_tool" \
        --output "$product_manifest"
}

product_build_manifest 02:00:00:00:00:01 >/dev/null
product_build_manifest 02:00:00:00:00:01 >/dev/null
if product_build_manifest 02:00:00:00:00:02 >/dev/null 2>&1; then
    echo "cross-device factory flash manifest was accepted" >&2
    exit 1
fi

echo "factory encrypted-flash manifest flow PASS: reproducible XTS ciphertext, exact NVS, raw-readback and cross-device rejection"
echo "physical-observation chain PASS with an ephemeral untrusted test key"
echo "readback inputs and station logs in this gate are simulated copies; no physical-board claim"
