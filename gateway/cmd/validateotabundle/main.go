package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/deploymentbundle"
)

func main() {
	bundle := flag.String("bundle", "", "path to the immutable OTA deployment bundle")
	authority := flag.String("authority", "", "canonical public firmware authority")
	flag.Parse()
	if flag.NArg() != 0 || *bundle == "" || *authority == "" {
		fmt.Fprintln(os.Stderr, "bundle and authority are required")
		os.Exit(2)
	}
	receipt, err := deploymentbundle.Validate(*bundle, *authority)
	if err != nil {
		fmt.Fprintln(os.Stderr, "OTA deployment bundle rejected:", err)
		os.Exit(1)
	}
	fmt.Printf("OTA deployment bundle verified: release=%s sequence=%d rollout=disabled\n",
		receipt.ReleaseID, receipt.ReleaseSequence)
}
