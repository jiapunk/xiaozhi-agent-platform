#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M72 qualification requires Go 1.26.5" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/providerrevocationqualification \
        ./internal/pushdelivery \
        ./cmd/qualifyproviderrevocation \
        ./cmd/signproviderrevocationattestation \
        ./cmd/buildproviderrevocationqualification \
        ./cmd/validateproviderrevocationqualification
    "$go_bin" vet \
        ./internal/providerrevocationqualification \
        ./internal/pushdelivery \
        ./cmd/qualifyproviderrevocation \
        ./cmd/signproviderrevocationattestation \
        ./cmd/buildproviderrevocationqualification \
        ./cmd/validateproviderrevocationqualification
)

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_provider_revocation_qualification_policy

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/smoke_provider_revocation_qualification.py" \
    --project "$project_dir" --go "$go_bin"

for schema in \
    provider-revocation-qualification-config.schema.json \
    provider-revocation-observation.schema.json \
    provider-revocation-attestation.schema.json \
    provider-revocation-qualification-receipt.schema.json \
    provider-revocation-evidence-manifest.schema.json
do
    python3 -m json.tool "$project_dir/gateway/$schema" >/dev/null
done

echo "M72 provider credential revocation software gate PASS"
echo "No live APNs/FCM console, provider API, cluster, App or market evidence is claimed"
