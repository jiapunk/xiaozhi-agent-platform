package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

func main() {
	receiptPath := flag.String("receipt", "", "signed qualification receipt")
	publicKeyPath := flag.String("trusted-public-key", "", "trusted Ed25519 public key")
	signingKeyID := flag.String("expected-signing-key-id", "", "expected signing key ID")
	qualificationID := flag.String("expected-qualification-id", "", "expected qualification ID")
	environment := flag.String("expected-environment", "", "expected staging or production environment")
	configDigest := flag.String("expected-config-sha256", "", "expected qualification config digest")
	toolDigest := flag.String("expected-tool-sha256", "", "expected qualification executable digest")
	requireLive := flag.Bool("require-live", false, "reject fixture-only evidence")
	flag.Parse()
	if flag.NArg() != 0 || *receiptPath == "" || *publicKeyPath == "" ||
		*signingKeyID == "" || *qualificationID == "" || *environment == "" ||
		*configDigest == "" || *toolDigest == "" {
		fail("all expected qualification identities are required")
	}
	receipt, err := pushqualification.VerifyReceiptFile(*receiptPath,
		pushqualification.VerifyOptions{
			TrustedPublicKey:        *publicKeyPath,
			ExpectedSigningKeyID:    *signingKeyID,
			ExpectedQualificationID: *qualificationID,
			ExpectedEnvironment:     *environment,
			ExpectedConfigSHA256:    *configDigest,
			ExpectedToolSHA256:      *toolDigest,
			RequireLive:             *requireLive,
		})
	if err != nil {
		fail("push qualification receipt rejected")
	}
	fmt.Printf("%s: %s\n", receipt.Result, *receiptPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
