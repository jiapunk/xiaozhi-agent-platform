package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/mtlsdispatchqualification"
)

func main() {
	observationPath := flag.String("observation", "", "canonical M71 transport observation")
	workloadEvidencePath := flag.String("workload-evidence", "",
		"bounded seven-service cluster evidence")
	provider := flag.String("attestation-provider", "",
		"kubernetes-cluster-authority or fixture")
	verifiedAtText := flag.String("verified-at", "", "trusted RFC3339 verification time")
	expiresAtText := flag.String("expires-at", "", "RFC3339 expiry within 24 hours")
	privateKeyPath := flag.String("signing-private-key", "",
		"deployment authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "deployment authority key ID")
	outputPath := flag.String("output", "", "new signed deployment attestation")
	acknowledge := flag.Bool("acknowledge-live-cluster-attestation", false,
		"acknowledge exact live seven-service, API admission, mounted identity and NetworkPolicy verification")
	flag.Parse()
	if flag.NArg() != 0 || *observationPath == "" ||
		*workloadEvidencePath == "" || *provider == "" ||
		*verifiedAtText == "" || *expiresAtText == "" ||
		*privateKeyPath == "" || *signingKeyID == "" || *outputPath == "" {
		fail("complete mTLS deployment attestation arguments are required")
	}
	observation, _, err := mtlsdispatchqualification.LoadObservation(
		*observationPath)
	if err != nil {
		fail("mTLS dispatch observation rejected")
	}
	if !observation.DevelopmentOnly && !*acknowledge {
		fail("live cluster attestation acknowledgement is required")
	}
	verifiedAt, err := time.Parse(time.RFC3339, *verifiedAtText)
	if err != nil || verifiedAt.Format(time.RFC3339) != *verifiedAtText {
		fail("trusted cluster verification time rejected")
	}
	expiresAt, err := time.Parse(time.RFC3339, *expiresAtText)
	if err != nil || expiresAt.Format(time.RFC3339) != *expiresAtText {
		fail("cluster attestation expiry rejected")
	}
	observationDigest, err := mtlsdispatchqualification.DigestRegularFile(
		*observationPath, 1<<20)
	if err != nil {
		fail("mTLS dispatch observation digest unavailable")
	}
	workloadDigest, err := mtlsdispatchqualification.DigestRegularFile(
		*workloadEvidencePath, 1<<20)
	if err != nil {
		fail("seven-service workload evidence rejected")
	}
	payload, err := mtlsdispatchqualification.SignAttestation(
		mtlsdispatchqualification.AttestationInput{Observation: observation,
			ObservationSHA256:      observationDigest,
			WorkloadEvidenceSHA256: workloadDigest, Provider: *provider,
			VerifiedAt: verifiedAt, ExpiresAt: expiresAt,
			DevelopmentOnly: observation.DevelopmentOnly},
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("mTLS deployment attestation signing failed")
	}
	if err := mtlsdispatchqualification.WriteNew(*outputPath, payload); err != nil {
		fail("mTLS deployment attestation publication failed")
	}
	fmt.Printf("mTLS deployment attestation: %s\n", *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
