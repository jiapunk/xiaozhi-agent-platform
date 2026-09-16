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
	configPath := flag.String("config", "", "private isolated restore config")
	failoverPath := flag.String("failover-observation", "",
		"canonical live failover observation")
	outputPath := flag.String("output", "", "new canonical restore observation")
	operationTimeout := flag.Duration("operation-timeout", 3*time.Second,
		"per-restored-database operation timeout")
	acknowledge := flag.Bool("acknowledge-live-isolated-point-in-time-restore", false,
		"acknowledge reads from all isolated managed database restores")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *failoverPath == "" ||
		*outputPath == "" || !*acknowledge {
		fail("complete arguments and isolated point-in-time restore acknowledgement are required")
	}
	executable, err := os.Executable()
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fail("qualification executable identity unavailable")
	}
	config, err := databasequalification.LoadLiveRestoreConfig(*configPath,
		*failoverPath, executable, *operationTimeout)
	if err != nil {
		fail("live managed database restore configuration rejected")
	}
	defer databasequalification.CloseRestoreConfig(config)
	runContext, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observation, err := databasequalification.NewRunner().RunRestore(
		runContext, config)
	if err != nil {
		fail("live managed database point-in-time restore qualification failed")
	}
	payload, err := databasequalification.CanonicalRestoreObservation(observation)
	if err != nil {
		fail("managed database restore observation serialization failed")
	}
	if err := databasequalification.WriteNew(*outputPath, payload); err != nil {
		fail("managed database restore observation publication failed")
	}
	fmt.Printf("managed database restore observation: %s\n", *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
