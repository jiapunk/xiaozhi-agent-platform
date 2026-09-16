#!/usr/bin/env sh
set -eu
umask 077

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir=${1:-"$product_project_dir/build-box3-production-security"}

if ! command -v python >/dev/null 2>&1 ||
   ! python -c 'import espsecure' >/dev/null 2>&1; then
    echo "ESP-IDF espsecure Python environment is unavailable" >&2
    exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "OpenSSL is unavailable" >&2
    exit 1
fi

product_temp_dir=$(mktemp -d /tmp/xz-security-signing.XXXXXX)
case "$product_temp_dir" in
    /tmp/xz-security-signing.*) ;;
    *) echo "unexpected signing test directory" >&2; exit 1 ;;
esac

product_key0="$product_temp_dir/key0.pem"
product_key1="$product_temp_dir/key1.pem"
product_key2="$product_temp_dir/key2.pem"
product_public0="$product_temp_dir/key0-public.pem"
product_public1="$product_temp_dir/key1-public.pem"
product_public2="$product_temp_dir/key2-public.pem"
product_app="$product_temp_dir/app-signed.bin"
product_boot0="$product_temp_dir/boot0.bin"
product_boot1="$product_temp_dir/boot1.bin"
product_boot2="$product_temp_dir/boot2.bin"
product_receipt="$product_temp_dir/signed-artifact-verification.json"
product_virtual_efuse_evidence="$product_temp_dir/virtual-efuse-rehearsal.json"

product_cleanup() {
    for product_file in \
        "$product_key0" "$product_key1" "$product_key2" \
        "$product_public0" "$product_public1" "$product_public2" \
        "$product_app" "$product_boot0" "$product_boot1" "$product_boot2" \
        "$product_receipt" "$product_virtual_efuse_evidence"; do
        if [ -f "$product_file" ]; then
            unlink "$product_file"
        fi
    done
    rmdir "$product_temp_dir" 2>/dev/null || true
}
trap product_cleanup EXIT HUP INT TERM

for product_key in "$product_key0" "$product_key1" "$product_key2"; do
    python -m espsecure generate-signing-key \
        --version 2 --scheme rsa3072 "$product_key" >/dev/null
done
openssl pkey -in "$product_key0" -pubout -out "$product_public0" 2>/dev/null
openssl pkey -in "$product_key1" -pubout -out "$product_public1" 2>/dev/null
openssl pkey -in "$product_key2" -pubout -out "$product_public2" 2>/dev/null

python -m espsecure sign-data --version 2 --keyfile "$product_key0" \
    --output "$product_app" \
    "$product_build_dir/xiaozhi_agent_platform.bin" >/dev/null

python -m espsecure sign-data --version 2 --keyfile "$product_key0" \
    --output "$product_boot0" \
    "$product_build_dir/bootloader/bootloader.bin" >/dev/null
python -m espsecure sign-data --version 2 --append-signatures \
    --keyfile "$product_key1" --output "$product_boot1" \
    "$product_boot0" >/dev/null
python -m espsecure sign-data --version 2 --append-signatures \
    --keyfile "$product_key2" --output "$product_boot2" \
    "$product_boot1" >/dev/null

python3 "$product_project_dir/tools/verify_production_signed_artifacts.py" \
    --espsecure-python "$(command -v python)" \
    --signing-request \
    "$product_build_dir/production-security-signing-request.json" \
    --signed-bootloader "$product_boot2" \
    --signed-application "$product_app" \
    --public-key "$product_public0" \
    --public-key "$product_public1" \
    --public-key "$product_public2" \
    --write-verification-receipt "$product_receipt"

python "$product_project_dir/tools/run_box3_virtual_efuse_rehearsal.py" \
    --signing-request \
    "$product_build_dir/production-security-signing-request.json" \
    --write-evidence "$product_virtual_efuse_evidence"
python "$product_project_dir/tools/verify_box3_virtual_efuse_rehearsal.py" \
    --evidence "$product_virtual_efuse_evidence" \
    --signing-request \
    "$product_build_dir/production-security-signing-request.json"

python "$product_project_dir/tools/test_sacrificial_provisioning_plan_flow.py" \
    --signing-request \
    "$product_build_dir/production-security-signing-request.json" \
    --signed-artifact-verification "$product_receipt"

"$product_project_dir/tools/test_factory_flash_manifest_flow.sh" \
    "$product_build_dir" "$product_boot2" "$product_app" "$product_receipt"

echo "ephemeral remote-signing flow PASS: bootloader 3/3 RSA signatures; app 1/1"
echo "virtual-eFuse lifecycle PASS: VIRTUAL_TEST_ONLY; no physical-device claim"
echo "sacrificial-plan contract PASS: synthetic preflight only; no execution authority"
echo "attempt-consumption ledger PASS: local synthetic one-time handoff; no executor"
echo "trusted-time contract PASS: signed synthetic subject; production consume is online mTLS only"
echo "all test private keys and signed test artifacts removed on exit"
