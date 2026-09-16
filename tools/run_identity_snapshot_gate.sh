#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gateway_dir="$project_dir/gateway"

if ! command -v go >/dev/null 2>&1; then
    echo "identity snapshot gate requires Go" >&2
    exit 2
fi
gate_dir=$(mktemp -d)
trap 'rm -rf -- "$gate_dir"' EXIT HUP INT TERM

private_key="$gate_dir/identity-private.pem"
public_key="$gate_dir/identity-public.pem"
unsigned_snapshot="$gate_dir/identity-unsigned.json"
signed_snapshot="$gate_dir/identity-signed.json"
tampered_snapshot="$gate_dir/identity-tampered.json"

(
    cd "$gateway_dir"
    go run ./cmd/generateidentitykey \
        -private-key-output "$private_key" \
        -public-key-output "$public_key"
)

python3 - "$unsigned_snapshot" <<'PY'
import datetime
import json
import os
import sys

now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
document = {
    "version": 2,
    "revision": 7001,
    "purpose": "access",
    "issued_at": now.isoformat().replace("+00:00", "Z"),
    "valid_until": (now + datetime.timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    "devices": [
        {"device_id": "box3-gate-001", "board": "esp32s3-box3", "ota_channel": "development"}
    ],
}
path = sys.argv[1]
with open(path, "x", encoding="utf-8") as output:
    json.dump(document, output, separators=(",", ":"))
    output.write("\n")
os.chmod(path, 0o600)
PY

(
    cd "$gateway_dir"
    go run ./cmd/signidentitysnapshot \
        -input "$unsigned_snapshot" \
        -private-key "$private_key" \
        -signing-key-id identity-gate-1 \
        -output "$signed_snapshot"
)

snapshot_digest=$(python3 - "$signed_snapshot" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as source:
    document = json.load(source)
canonical = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
print(hashlib.sha256(canonical).hexdigest())
PY
)

(
    cd "$gateway_dir"
    go run ./cmd/validateidentitysnapshot \
        -snapshot "$signed_snapshot" \
        -public-key "$public_key" \
        -signing-key-id identity-gate-1 \
        -expect-revision 7001 \
        -expect-purpose access \
        -expect-digest-sha256 "$snapshot_digest"
)

cp "$signed_snapshot" "$tampered_snapshot"
python3 - "$tampered_snapshot" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_text(encoding="utf-8")
payload = payload.replace('"revision": 7001', '"revision": 7002', 1)
path.write_text(payload, encoding="utf-8")
PY
chmod 600 "$tampered_snapshot"
if (
    cd "$gateway_dir"
    go run ./cmd/validateidentitysnapshot \
        -snapshot "$tampered_snapshot" \
        -public-key "$public_key" \
        -signing-key-id identity-gate-1 \
        -expect-revision 7001 \
        -expect-purpose access \
        -expect-digest-sha256 "$snapshot_digest" >/dev/null 2>&1
); then
    echo "tampered identity snapshot unexpectedly passed" >&2
    exit 1
fi

chmod 644 "$signed_snapshot"
if (
    cd "$gateway_dir"
    go run ./cmd/validateidentitysnapshot \
        -snapshot "$signed_snapshot" \
        -public-key "$public_key" \
        -signing-key-id identity-gate-1 \
        -expect-revision 7001 \
        -expect-purpose access \
        -expect-digest-sha256 "$snapshot_digest" >/dev/null 2>&1
); then
    echo "broadly readable identity snapshot unexpectedly passed" >&2
    exit 1
fi

(
    cd "$gateway_dir"
    go test -count=1 \
        ./internal/identityconfig \
        ./internal/identityruntime \
        ./internal/provisioning \
        ./internal/identityaccess \
        ./internal/gateway \
        ./internal/controlplane \
        ./internal/agentproxy \
        ./internal/firmwareorigin \
        ./internal/integration
)

echo "identity snapshot gate passed: revision=7001 digest_sha256=$snapshot_digest"
