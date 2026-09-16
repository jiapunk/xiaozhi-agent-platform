package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/ocirelease"
)

func main() {
	bundle := flag.String("bundle", "", "immutable OCI release bundle directory")
	publicKey := flag.String("public-key", "", "trusted external Ed25519 public key PEM")
	keyID := flag.String("key-id", "", "expected release signing key ID")
	releaseID := flag.String("release-id", "", "optional expected release ID")
	flag.Parse()
	if *bundle == "" || *publicKey == "" || *keyID == "" {
		fmt.Fprintln(os.Stderr, "-bundle, -public-key, and -key-id are required")
		os.Exit(2)
	}
	receipt, err := ocirelease.Validate(*bundle, ocirelease.Options{
		TrustedPublicKey:  *publicKey,
		SigningKeyID:      *keyID,
		ExpectedReleaseID: *releaseID,
		RequireReadOnly:   true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "OCI release verification failed:", err)
		os.Exit(1)
	}
	fmt.Printf("OCI release verified release=%s services=%d signature=Ed25519\n",
		receipt.ReleaseID, len(receipt.Services))
}
