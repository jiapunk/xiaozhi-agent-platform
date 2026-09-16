package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/providerrevocationqualification"
)

func main() {
	observationPath := flag.String("observation", "", "canonical M72 revocation observation")
	auditEvidencePath := flag.String("provider-audit-evidence", "",
		"bounded provider console and WORM audit evidence")
	provider := flag.String("attestation-provider", "",
		"provider-credential-audit-authority or fixture")
	changeStartedText := flag.String("revocation-change-started-at", "",
		"trusted RFC3339 provider change start")
	changeCompletedText := flag.String("revocation-change-completed-at", "",
		"trusted RFC3339 provider change completion")
	verifiedAtText := flag.String("verified-at", "", "trusted RFC3339 verification time")
	expiresAtText := flag.String("expires-at", "", "RFC3339 expiry within 24 hours")
	privateKeyPath := flag.String("signing-private-key", "",
		"credential audit authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "credential audit authority key ID")
	outputPath := flag.String("output", "", "new signed provider revocation attestation")
	acknowledge := flag.Bool("acknowledge-live-provider-console-revocation", false,
		"acknowledge console revocation, active key and WORM evidence verification")
	flag.Parse()
	if flag.NArg() != 0 || *observationPath == "" || *auditEvidencePath == "" ||
		*provider == "" || *changeStartedText == "" || *changeCompletedText == "" ||
		*verifiedAtText == "" || *expiresAtText == "" || *privateKeyPath == "" ||
		*signingKeyID == "" || *outputPath == "" {
		fail("complete provider revocation attestation arguments are required")
	}
	observation, _, err := providerrevocationqualification.LoadObservation(
		*observationPath)
	if err != nil {
		fail("provider revocation observation rejected")
	}
	if !observation.DevelopmentOnly && !*acknowledge {
		fail("live provider console revocation acknowledgement is required")
	}
	changeStarted := parseTime(*changeStartedText, "revocation change start rejected")
	changeCompleted := parseTime(*changeCompletedText, "revocation change completion rejected")
	verifiedAt := parseTime(*verifiedAtText, "provider audit verification time rejected")
	expiresAt := parseTime(*expiresAtText, "provider audit expiry rejected")
	observationDigest, err := providerrevocationqualification.DigestRegularFile(
		*observationPath, 1<<20)
	if err != nil {
		fail("provider revocation observation digest unavailable")
	}
	auditDigest, err := providerrevocationqualification.DigestRegularFile(
		*auditEvidencePath, 1<<20)
	if err != nil {
		fail("provider console audit evidence rejected")
	}
	payload, err := providerrevocationqualification.SignAttestation(
		providerrevocationqualification.AttestationInput{Observation: observation,
			ObservationSHA256:           observationDigest,
			ProviderAuditEvidenceSHA256: auditDigest, Provider: *provider,
			RevocationChangeStartedAt:   changeStarted,
			RevocationChangeCompletedAt: changeCompleted,
			VerifiedAt:                  verifiedAt, ExpiresAt: expiresAt,
			DevelopmentOnly: observation.DevelopmentOnly},
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("provider revocation attestation signing failed")
	}
	if err := providerrevocationqualification.WriteNew(*outputPath, payload); err != nil {
		fail("provider revocation attestation publication failed")
	}
	fmt.Printf("provider revocation attestation: %s\n", *outputPath)
}

func parseTime(value, message string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		fail(message)
	}
	return parsed
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
