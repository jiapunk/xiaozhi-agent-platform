package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

func main() {
	snapshotPath := flag.String("snapshot", "", "signed confidential identity snapshot")
	publicKeyPath := flag.String("public-key", "", "trusted Ed25519 public key")
	signingKeyID := flag.String("signing-key-id", "", "expected signing key identifier")
	expectedRevision := flag.Uint64("expect-revision", 0, "externally expected monotonic revision")
	expectedPurpose := flag.String("expect-purpose", "", "externally expected access or proof purpose")
	expectedDigest := flag.String("expect-digest-sha256", "", "externally expected canonical signed digest")
	flag.Parse()
	if *snapshotPath == "" || *publicKeyPath == "" || *signingKeyID == "" ||
		*expectedRevision == 0 || (*expectedPurpose != provisioning.AccessSnapshotPurpose &&
		*expectedPurpose != provisioning.ProofSnapshotPurpose) || len(*expectedDigest) != 64 {
		fatal("snapshot, public-key, signing-key-id, expect-revision, expect-purpose, and 64-character expect-digest-sha256 are required")
	}
	publicKey, err := provisioning.LoadEd25519PublicKey(*publicKeyPath)
	if err != nil {
		fatal(err.Error())
	}
	snapshot, err := provisioning.LoadSignedRegistrySnapshot(*snapshotPath,
		publicKey, *signingKeyID, time.Now().UTC())
	if err != nil {
		fatal(err.Error())
	}
	registry, err := provisioning.NewRegistryFromSnapshot(snapshot, time.Now)
	if err != nil {
		fatal(err.Error())
	}
	status := registry.Status()
	if status.Revision != *expectedRevision || status.Purpose != *expectedPurpose ||
		!strings.EqualFold(status.DigestSHA256, *expectedDigest) || !status.Ready {
		fatal("device identity snapshot does not match external expectations")
	}
	fmt.Printf("device identity snapshot valid: revision=%d digest_sha256=%s valid_until=%s\n",
		status.Revision, status.DigestSHA256,
		status.ValidUntil.UTC().Format(time.RFC3339))
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
