package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

func main() {
	configPath := flag.String("config", "", "private live qualification config")
	privateKeyPath := flag.String("signing-private-key", "", "Ed25519 approval private key")
	signingKeyID := flag.String("signing-key-id", "", "approval signing key ID")
	outputPath := flag.String("output", "", "new signed receipt path")
	providerTimeout := flag.Duration("provider-timeout", 10*time.Second,
		"per-provider HTTP timeout")
	acknowledge := flag.Bool("acknowledge-live-provider-calls", false,
		"acknowledge that fixed wakes will be sent to staging/production providers")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *privateKeyPath == "" ||
		*signingKeyID == "" || *outputPath == "" || !*acknowledge {
		fail("complete arguments and --acknowledge-live-provider-calls are required")
	}
	config, err := pushqualification.LoadLiveConfig(*configPath, *providerTimeout)
	if err != nil {
		fail("live provider configuration rejected")
	}
	executable, err := os.Executable()
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	config.ToolSHA256, err = pushqualification.DigestRegularFile(
		executable, 256*1024*1024)
	if err != nil {
		fail("qualification executable rejected")
	}
	runContext, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	receipt, err := pushqualification.NewRunner().Run(runContext, config)
	if err != nil {
		fail("live provider qualification failed")
	}
	payload, err := pushqualification.SignReceipt(receipt,
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("qualification receipt signing failed")
	}
	if err := pushqualification.WriteNewReceipt(*outputPath, payload); err != nil {
		fail("qualification receipt publication failed")
	}
	fmt.Printf("%s: %s\n", pushqualification.LiveResult, *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
