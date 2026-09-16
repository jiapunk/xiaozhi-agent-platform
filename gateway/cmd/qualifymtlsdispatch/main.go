package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/mtlsdispatchqualification"
)

func main() {
	configPath := flag.String("config", "", "private live mTLS dispatch config")
	outputPath := flag.String("output", "", "new canonical transport observation")
	requestTimeout := flag.Duration("request-timeout", 2*time.Second,
		"private wake request timeout")
	acknowledge := flag.Bool("acknowledge-live-mtls-dispatch", false,
		"acknowledge real current/next wakes and negative TLS probes")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *outputPath == "" ||
		!*acknowledge {
		fail("complete arguments and --acknowledge-live-mtls-dispatch are required")
	}
	config, err := mtlsdispatchqualification.LoadLiveConfig(
		*configPath, *requestTimeout)
	if err != nil {
		fail("live mTLS dispatch configuration rejected")
	}
	executable, err := os.Executable()
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	config.ToolSHA256, err = mtlsdispatchqualification.DigestRegularFile(
		executable, 256*1024*1024)
	if err != nil {
		fail("qualification executable rejected")
	}
	runContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	observation, err := mtlsdispatchqualification.NewRunner().Run(
		runContext, config)
	if err != nil {
		fail("live mTLS dispatch qualification failed")
	}
	payload, err := mtlsdispatchqualification.CanonicalObservation(observation)
	if err != nil {
		fail("mTLS dispatch observation serialization failed")
	}
	if err := mtlsdispatchqualification.WriteNew(*outputPath, payload); err != nil {
		fail("mTLS dispatch observation publication failed")
	}
	fmt.Printf("mTLS dispatch observation: %s\n", *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
