package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/databasequalification"
)

func main() {
	configPath := flag.String("config", "", "private managed database failover config")
	readyPath := flag.String("ready-output", "", "new public failover ready signal")
	outputPath := flag.String("output", "", "new canonical failover observation")
	operationTimeout := flag.Duration("operation-timeout", 3*time.Second,
		"per-database operation timeout")
	heartbeatInterval := flag.Duration("heartbeat-interval", time.Second,
		"durable failover heartbeat interval")
	failoverTimeout := flag.Duration("failover-timeout", 10*time.Minute,
		"maximum wait for all managed primaries to change")
	acknowledge := flag.Bool("acknowledge-live-managed-database-failover", false,
		"acknowledge writes and externally initiated failover of all configured databases")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *readyPath == "" ||
		*outputPath == "" || *readyPath == *outputPath || !*acknowledge {
		fail("complete arguments and live managed database failover acknowledgement are required")
	}
	executable, err := os.Executable()
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	config, err := databasequalification.LoadLiveFailoverConfig(
		*configPath, executable, *operationTimeout, *heartbeatInterval,
		*failoverTimeout)
	if err != nil {
		fail("live managed database failover configuration rejected")
	}
	defer databasequalification.CloseFailoverConfig(config)
	config.SignalReady = func(signal databasequalification.ReadySignal) (string, error) {
		payload, marshalErr := databasequalification.CanonicalReadySignal(signal)
		if marshalErr != nil {
			return "", marshalErr
		}
		if writeErr := databasequalification.WriteNew(*readyPath, payload); writeErr != nil {
			return "", writeErr
		}
		return databasequalification.DigestRegularFile(
			*readyPath, 1<<20)
	}
	runContext, cancel := context.WithTimeout(context.Background(),
		*failoverTimeout+time.Minute)
	defer cancel()
	observation, err := databasequalification.NewRunner().RunFailover(
		runContext, config)
	if err != nil {
		fail("live managed database failover qualification failed")
	}
	payload, err := databasequalification.CanonicalFailoverObservation(observation)
	if err != nil {
		fail("managed database failover observation serialization failed")
	}
	if err := databasequalification.WriteNew(*outputPath, payload); err != nil {
		fail("managed database failover observation publication failed")
	}
	fmt.Printf("managed database failover observation: %s\n", *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
