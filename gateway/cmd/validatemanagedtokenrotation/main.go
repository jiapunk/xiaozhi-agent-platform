package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const preflightSchema = "xz-managed-token-rotation-preflight-v1"

type preflightReceipt struct {
	Schema                string `json:"schema"`
	Result                string `json:"result"`
	SoftwareOnly          bool   `json:"software_only"`
	Domain                string `json:"domain"`
	Transition            string `json:"transition"`
	ObservedAtUnix        int64  `json:"observed_at_unix"`
	MaxTokenTTLSeconds    int64  `json:"max_token_ttl_seconds"`
	CurrentRevision       uint64 `json:"current_revision"`
	TargetRevision        uint64 `json:"target_revision"`
	CurrentActiveKeyID    string `json:"current_active_key_id"`
	TargetActiveKeyID     string `json:"target_active_key_id"`
	CutoverUnix           int64  `json:"cutover_unix"`
	MinimumDrainUntilUnix int64  `json:"minimum_drain_until_unix"`
	OldKeyVerifyUntilUnix int64  `json:"old_key_verify_until_unix"`
}

func main() {
	if err := run(os.Args[1:], time.Now); err != nil {
		fmt.Fprintln(os.Stderr, "managed token rotation preflight rejected:", err)
		os.Exit(2)
	}
}

func run(arguments []string, clock func() time.Time) error {
	flags := flag.NewFlagSet("validatemanagedtokenrotation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	domain := flags.String("domain", "", "voice, agent, or ota")
	transition := flags.String("transition", "", "rotate or forward-recovery")
	currentFile := flags.String("current-keyring", "", "current issuer keyring file")
	currentFloor := flags.Uint64("current-min-revision", 0, "approved current revision floor")
	targetFile := flags.String("target-keyring", "", "target verifier keyring file")
	targetFloor := flags.Uint64("target-min-revision", 0, "approved target revision floor")
	expectedCurrentRevision := flags.Uint64(
		"expected-current-revision", 0, "exact current document revision")
	expectedTargetRevision := flags.Uint64(
		"expected-target-revision", 0, "exact target document revision")
	expectedCurrentKey := flags.String(
		"expected-current-active-key-id", "", "exact current active key ID")
	expectedTargetKey := flags.String(
		"expected-target-active-key-id", "", "exact target active key ID")
	maxTTLSeconds := flags.Int64(
		"max-token-ttl-seconds", 0, "domain verifier maximum token TTL")
	output := flags.String("output", "", "new canonical nonsecret receipt")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return fmt.Errorf("complete canonical arguments are required")
	}
	if (*domain != "voice" && *domain != "agent" && *domain != "ota") ||
		(*transition != auth.ManagedTokenTransitionRotate &&
			*transition != auth.ManagedTokenTransitionForwardRecover) ||
		*currentFile == "" || *targetFile == "" || *output == "" ||
		*currentFloor == 0 || *targetFloor == 0 ||
		*expectedCurrentRevision == 0 || *expectedTargetRevision == 0 ||
		*currentFloor != *expectedCurrentRevision ||
		*targetFloor != *expectedTargetRevision ||
		!auth.ValidIdentifier(*expectedCurrentKey, 64) ||
		!auth.ValidIdentifier(*expectedTargetKey, 64) ||
		*maxTTLSeconds < 60 || *maxTTLSeconds > 3600 || clock == nil {
		return fmt.Errorf("complete bounded preflight arguments are required")
	}
	now := clock().UTC().Truncate(time.Second)
	if now.IsZero() {
		return fmt.Errorf("preflight clock is invalid")
	}
	current, err := auth.LoadManagedTokenKeyring(*currentFile, *currentFloor, now)
	if err != nil {
		return fmt.Errorf("current keyring rejected: %w", err)
	}
	target, err := auth.LoadManagedTokenKeyring(*targetFile, *targetFloor, now)
	if err != nil {
		return fmt.Errorf("target keyring rejected: %w", err)
	}
	summary, err := auth.ValidateManagedTokenTransition(
		current, target, *transition,
		time.Duration(*maxTTLSeconds)*time.Second, now)
	if err != nil {
		return err
	}
	if summary.CurrentRevision != *expectedCurrentRevision ||
		summary.TargetRevision != *expectedTargetRevision ||
		summary.CurrentActiveKeyID != *expectedCurrentKey ||
		summary.TargetActiveKeyID != *expectedTargetKey {
		return fmt.Errorf("keyring metadata does not match operator expectations")
	}
	receipt := preflightReceipt{
		Schema: preflightSchema, Result: "SOFTWARE_PREFLIGHT_PASS",
		SoftwareOnly: true, Domain: *domain, Transition: summary.Transition,
		ObservedAtUnix: now.Unix(), MaxTokenTTLSeconds: *maxTTLSeconds,
		CurrentRevision:       summary.CurrentRevision,
		TargetRevision:        summary.TargetRevision,
		CurrentActiveKeyID:    summary.CurrentActiveKeyID,
		TargetActiveKeyID:     summary.TargetActiveKeyID,
		CutoverUnix:           summary.CutoverUnix,
		MinimumDrainUntilUnix: summary.MinimumDrainUntilUnix,
		OldKeyVerifyUntilUnix: summary.OldKeyVerifyUntilUnix,
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode preflight receipt: %w", err)
	}
	return writeReceipt(*output, payload)
}

func writeReceipt(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create new preflight receipt: %w", err)
	}
	complete := false
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if written, writeErr := file.Write(payload); writeErr != nil ||
		written != len(payload) {
		return fmt.Errorf("write preflight receipt")
	}
	if err := file.Chmod(0o444); err != nil {
		return fmt.Errorf("protect preflight receipt: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync preflight receipt: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close preflight receipt: %w", err)
	}
	closed = true
	complete = true
	return nil
}
