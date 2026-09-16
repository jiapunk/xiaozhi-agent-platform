#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
third_party_dir="$project_dir/third_party"

xiaozhi_url="https://github.com/78/xiaozhi-esp32.git"
xiaozhi_commit="18a60b8051f5ee6a25beed6248ed84c7fcc742bf"
claw_url="https://github.com/espressif/esp-claw.git"
claw_commit="9ba07d013329df480e34a1a59d1513ab783d8a52"

sync_repo() {
    repo_name=$1
    repo_url=$2
    repo_commit=$3
    repo_dir="$third_party_dir/$repo_name"

    if [ ! -d "$repo_dir/.git" ]; then
        mkdir -p "$repo_dir"
        GIT_CONFIG_GLOBAL=/dev/null git -C "$repo_dir" init
        GIT_CONFIG_GLOBAL=/dev/null git -C "$repo_dir" remote add origin "$repo_url"
    fi

    GIT_CONFIG_GLOBAL=/dev/null git -C "$repo_dir" fetch --depth 1 origin "$repo_commit"
    GIT_CONFIG_GLOBAL=/dev/null git -C "$repo_dir" checkout --detach --force FETCH_HEAD
    actual_commit=$(git -C "$repo_dir" rev-parse HEAD)
    if [ "$actual_commit" != "$repo_commit" ]; then
        echo "Commit verification failed for $repo_name" >&2
        exit 1
    fi
    echo "$repo_name locked at $actual_commit"
}

mkdir -p "$third_party_dir"
sync_repo "xiaozhi-esp32" "$xiaozhi_url" "$xiaozhi_commit"
sync_repo "esp-claw" "$claw_url" "$claw_commit"

esp_claw_patch="$project_dir/patches/esp-claw/0001-redact-agent-content-logs.patch"
if [ ! -f "$esp_claw_patch" ]; then
    echo "Required ESP-Claw product privacy patch is missing" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    actual_patch_sha=$(sha256sum "$esp_claw_patch" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual_patch_sha=$(shasum -a 256 "$esp_claw_patch" | awk '{print $1}')
else
    actual_patch_sha=$(openssl dgst -sha256 "$esp_claw_patch" | awk '{print $NF}')
fi
expected_patch_sha="8c239b7eb5a1875ffb211cb65bef96ffa988561b2e373e594626a6011a344316"
if [ "$actual_patch_sha" != "$expected_patch_sha" ]; then
    echo "ESP-Claw product privacy patch digest mismatch" >&2
    exit 1
fi
GIT_CONFIG_GLOBAL=/dev/null git -C "$third_party_dir/esp-claw" \
    apply --check "$esp_claw_patch"
GIT_CONFIG_GLOBAL=/dev/null git -C "$third_party_dir/esp-claw" \
    apply "$esp_claw_patch"
echo "esp-claw product privacy patch applied at $actual_patch_sha"
