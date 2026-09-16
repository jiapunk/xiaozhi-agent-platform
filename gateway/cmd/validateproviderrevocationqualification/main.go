package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/providerrevocationqualification"
)

func main() {
	receiptPath := flag.String("receipt", "", "signed M72 receipt")
	publicKeyPath := flag.String("trusted-public-key", "",
		"trusted M72 final authority public key")
	signingKeyID := flag.String("expected-signing-key-id", "",
		"expected M72 final authority key ID")
	manifestPath := flag.String("evidence-manifest", "",
		"independently sourced public M69 through M72 evidence manifest")
	requireLive := flag.Bool("require-live", false, "reject every fixture in the chain")
	flag.Parse()
	if flag.NArg() != 0 || *receiptPath == "" || *publicKeyPath == "" ||
		*signingKeyID == "" || *manifestPath == "" {
		fail("all provider revocation qualification trust inputs are required")
	}
	evidence, verify, err := providerrevocationqualification.LoadEvidenceManifest(
		*manifestPath, *requireLive)
	if err != nil {
		fail("provider revocation evidence manifest rejected")
	}
	verify.TrustedPublicKey = *publicKeyPath
	verify.ExpectedSigningKeyID = *signingKeyID
	verified, err := providerrevocationqualification.VerifyReceiptFile(
		*receiptPath, verify)
	if err != nil {
		fail("provider revocation qualification receipt rejected")
	}
	expected, err := providerrevocationqualification.BuildReceipt(evidence)
	if err != nil || !providerrevocationqualification.ReceiptMatchesEvidence(
		verified, expected) {
		fail("provider revocation qualification evidence bundle rejected")
	}
	fmt.Printf("%s: %s\n", verified.Result, *receiptPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
