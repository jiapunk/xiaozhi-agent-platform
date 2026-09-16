package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/appdeliveryqualification"
)

func main() {
	observationPath := flag.String("observation", "", "canonical App flow observation")
	providerReceiptPath := flag.String("provider-receipt", "", "completed M69 receipt to bind")
	vendorEvidencePath := flag.String("vendor-evidence", "", "bounded vendor attestation evidence")
	attestedKeySHA := flag.String("attested-key-sha256", "", "attested App key SHA-256")
	provider := flag.String("attestation-provider", "", "apple-app-attest or fixture")
	verifiedAtText := flag.String("verified-at", "", "trusted RFC3339 verification time")
	expiresAtText := flag.String("expires-at", "", "RFC3339 expiry within 24 hours")
	privateKeyPath := flag.String("signing-private-key", "", "attestation authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "attestation authority key ID")
	outputPath := flag.String("output", "", "new signed attestation receipt")
	acknowledge := flag.Bool("acknowledge-live-vendor-attestation", false,
		"acknowledge independent vendor attestation and signed artifact verification")
	flag.Parse()
	if flag.NArg() != 0 || *observationPath == "" || *providerReceiptPath == "" ||
		*vendorEvidencePath == "" ||
		*attestedKeySHA == "" || *provider == "" || *verifiedAtText == "" ||
		*expiresAtText == "" || *privateKeyPath == "" || *signingKeyID == "" ||
		*outputPath == "" {
		fail("complete App attestation arguments are required")
	}
	observation, _, err :=
		appdeliveryqualification.LoadObservation(*observationPath)
	if err != nil {
		fail("App delivery observation rejected")
	}
	if !observation.DevelopmentOnly && !*acknowledge {
		fail("live App attestation acknowledgement is required")
	}
	verifiedAt, err := time.Parse(time.RFC3339, *verifiedAtText)
	if err != nil || verifiedAt.Format(time.RFC3339) != *verifiedAtText {
		fail("trusted App attestation verification time rejected")
	}
	expiresAt, err := time.Parse(time.RFC3339, *expiresAtText)
	if err != nil || expiresAt.Format(time.RFC3339) != *expiresAtText {
		fail("App attestation expiry rejected")
	}
	vendorDigest, err := appdeliveryqualification.DigestRegularFile(
		*vendorEvidencePath, 1<<20)
	if err != nil {
		fail("vendor attestation evidence rejected")
	}
	observationDigest, err := appdeliveryqualification.DigestRegularFile(
		*observationPath, 1<<20)
	if err != nil {
		fail("App delivery observation digest unavailable")
	}
	providerReceiptDigest, err := appdeliveryqualification.DigestRegularFile(
		*providerReceiptPath, 1<<20)
	if err != nil {
		fail("provider qualification receipt digest unavailable")
	}
	payload, err := appdeliveryqualification.SignAttestation(
		appdeliveryqualification.AttestationInput{Observation: observation,
			ObservationSHA256:                  observationDigest,
			ProviderQualificationReceiptSHA256: providerReceiptDigest,
			VendorEvidenceSHA256:               vendorDigest,
			AttestedKeySHA256:                  *attestedKeySHA, Provider: *provider,
			VerifiedAt: verifiedAt, ExpiresAt: expiresAt,
			DevelopmentOnly: observation.DevelopmentOnly},
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("App attestation receipt signing failed")
	}
	if err := appdeliveryqualification.WriteNew(*outputPath, payload); err != nil {
		fail("App attestation receipt publication failed")
	}
	fmt.Printf("App attestation receipt: %s\n", *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
