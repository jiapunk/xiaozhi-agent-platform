package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/databasequalification"
)

func main() {
	receiptPath := flag.String("receipt", "", "signed M73 receipt")
	publicKeyPath := flag.String("trusted-public-key", "", "trusted M73 final authority public key")
	signingKeyID := flag.String("expected-signing-key-id", "", "expected M73 final authority key ID")
	manifestPath := flag.String("evidence-manifest", "", "independently sourced public M69 through M73 evidence manifest")
	requireLive := flag.Bool("require-live", false, "reject every fixture in the evidence chain")
	flag.Parse()
	if flag.NArg() != 0 || *receiptPath == "" || *publicKeyPath == "" ||
		*signingKeyID == "" || *manifestPath == "" {
		fail("all managed database qualification trust inputs are required")
	}
	evidence, verify, err := databasequalification.LoadDatabaseEvidenceManifest(
		*manifestPath, *requireLive)
	if err != nil {
		fail("managed database evidence manifest rejected")
	}
	verify.TrustedPublicKey = *publicKeyPath
	verify.ExpectedSigningKeyID = *signingKeyID
	verified, err := databasequalification.VerifyDatabaseReceiptFile(
		*receiptPath, verify)
	if err != nil {
		fail("managed database qualification receipt rejected")
	}
	expected, err := databasequalification.BuildDatabaseReceipt(evidence)
	if err != nil || !databasequalification.DatabaseReceiptMatchesEvidence(
		verified, expected) {
		fail("managed database qualification evidence bundle rejected")
	}
	fmt.Printf("%s: %s\n", verified.Result, *receiptPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
