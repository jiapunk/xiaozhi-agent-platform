package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

const fixtureTarget = "abababababababababababababababababababababababababababababababab"

type fixtureProvider struct{}

func (fixtureProvider) Send(ctx context.Context,
	target string) (pushdelivery.DeliveryResult, error) {
	if ctx.Err() != nil {
		return pushdelivery.DeliveryRetry, pushdelivery.ErrUnavailable
	}
	if target == fixtureTarget {
		return pushdelivery.DeliveryAccepted, nil
	}
	return pushdelivery.DeliveryInvalidInstallation, nil
}

func main() {
	qualificationID := flag.String("qualification-id", "", "fixture qualification ID")
	privateKeyPath := flag.String("signing-private-key", "", "Ed25519 fixture private key")
	signingKeyID := flag.String("signing-key-id", "", "fixture signing key ID")
	outputPath := flag.String("output", "", "new fixture receipt path")
	flag.Parse()
	if flag.NArg() != 0 || *qualificationID == "" || *privateKeyPath == "" ||
		*signingKeyID == "" || *outputPath == "" {
		fail("complete fixture arguments are required")
	}
	executable, err := os.Executable()
	if err != nil {
		fail("fixture executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fail("fixture executable identity unavailable")
	}
	toolDigest, err := pushqualification.DigestRegularFile(
		executable, 256*1024*1024)
	if err != nil {
		fail("fixture executable rejected")
	}
	configDigest := sha256.Sum256([]byte(
		"xz-push-provider-qualification-fixture-v1"))
	provider := fixtureProvider{}
	receipt, err := pushqualification.NewRunner().Run(context.Background(),
		pushqualification.RunConfig{QualificationID: *qualificationID,
			Environment: "staging", ConfigSHA256: hex.EncodeToString(configDigest[:]),
			ToolSHA256: toolDigest, DevelopmentOnly: true,
			Candidates: []pushqualification.Candidate{{
				Platform:      accountauth.PushPlatformAPNSDevelopment,
				ApplicationID: "com.example.product", CurrentCredentialID: "fixture-current-1",
				NextCredentialID: "fixture-next-2", Current: provider, Next: provider,
				ValidTarget: fixtureTarget,
			}},
		})
	if err != nil {
		fail("fixture qualification failed")
	}
	payload, err := pushqualification.SignReceipt(receipt,
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("fixture receipt signing failed")
	}
	if err := pushqualification.WriteNewReceipt(*outputPath, payload); err != nil {
		fail("fixture receipt publication failed")
	}
	fmt.Printf("%s: %s\n", pushqualification.FixtureResult, *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
