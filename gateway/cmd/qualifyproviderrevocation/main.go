package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/providerrevocationqualification"
)

func main() {
	configPath := flag.String("config", "", "private live provider revocation config")
	outputPath := flag.String("output", "", "new canonical revocation observation")
	providerTimeout := flag.Duration("provider-timeout", 10*time.Second,
		"per-provider HTTP timeout")
	acknowledge := flag.Bool("acknowledge-live-provider-credential-revocation", false,
		"acknowledge active/revoked/active calls to real provider APIs")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *outputPath == "" ||
		!*acknowledge {
		fail("complete arguments and live provider revocation acknowledgement are required")
	}
	config, err := providerrevocationqualification.LoadLiveConfig(
		*configPath, *providerTimeout)
	if err != nil {
		fail("live provider revocation configuration rejected")
	}
	executable, err := os.Executable()
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	config.ToolSHA256, err = providerrevocationqualification.DigestRegularFile(
		executable, 256*1024*1024)
	if err != nil {
		fail("qualification executable rejected")
	}
	runContext, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	observation, err := providerrevocationqualification.NewRunner().Run(
		runContext, config)
	if err != nil {
		fail("live provider credential revocation qualification failed")
	}
	payload, err := providerrevocationqualification.CanonicalObservation(observation)
	if err != nil {
		fail("provider revocation observation serialization failed")
	}
	if err := providerrevocationqualification.WriteNew(*outputPath, payload); err != nil {
		fail("provider revocation observation publication failed")
	}
	fmt.Printf("provider revocation observation: %s\n", *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
