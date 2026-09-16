package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/providerrevocationqualification"
)

func main() {
	manifestPath := flag.String("evidence-manifest", "",
		"strict public M69 through M72 evidence manifest")
	privateKeyPath := flag.String("signing-private-key", "",
		"M72 final authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "M72 final authority key ID")
	outputPath := flag.String("output", "", "new signed M72 receipt")
	acknowledge := flag.Bool("acknowledge-live-provider-credential-revocation", false,
		"acknowledge live provider, App, cluster and revocation evidence")
	flag.Parse()
	if flag.NArg() != 0 || *manifestPath == "" || *privateKeyPath == "" ||
		*signingKeyID == "" || *outputPath == "" {
		fail("complete provider revocation qualification arguments are required")
	}
	evidence, _, err := providerrevocationqualification.LoadEvidenceManifest(
		*manifestPath, false)
	if err != nil {
		fail("provider revocation evidence manifest rejected")
	}
	observation, _, err := providerrevocationqualification.LoadObservation(
		evidence.ObservationPath)
	if err != nil {
		fail("provider revocation observation rejected")
	}
	requireLive := !observation.DevelopmentOnly
	if requireLive && !*acknowledge {
		fail("live provider credential revocation acknowledgement is required")
	}
	if requireLive {
		evidence, _, err = providerrevocationqualification.LoadEvidenceManifest(
			*manifestPath, true)
		if err != nil {
			fail("live provider revocation evidence manifest rejected")
		}
	}
	receipt, err := providerrevocationqualification.BuildReceipt(evidence)
	if err != nil {
		fail("provider revocation qualification evidence rejected")
	}
	payload, err := providerrevocationqualification.SignReceipt(
		receipt, *privateKeyPath, *signingKeyID)
	if err != nil {
		fail("provider revocation qualification receipt signing failed")
	}
	if err := providerrevocationqualification.WriteNew(*outputPath, payload); err != nil {
		fail("provider revocation qualification receipt publication failed")
	}
	fmt.Printf("%s: %s\n", receipt.Result, *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
