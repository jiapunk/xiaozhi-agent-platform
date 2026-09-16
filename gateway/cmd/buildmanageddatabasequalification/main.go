package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/databasequalification"
)

func main() {
	manifestPath := flag.String("evidence-manifest", "", "strict public M69 through M73 evidence manifest")
	privateKeyPath := flag.String("signing-private-key", "", "M73 final authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "M73 final authority key ID")
	outputPath := flag.String("output", "", "new signed M73 receipt")
	acknowledge := flag.Bool("acknowledge-live-managed-database-qualification", false,
		"acknowledge all live provider, App, cluster, revocation and database evidence")
	flag.Parse()
	if flag.NArg() != 0 || *manifestPath == "" || *privateKeyPath == "" ||
		*signingKeyID == "" || *outputPath == "" {
		fail("complete managed database qualification arguments are required")
	}
	evidence, _, err := databasequalification.LoadDatabaseEvidenceManifest(
		*manifestPath, false)
	if err != nil {
		fail("managed database evidence manifest rejected")
	}
	failover, _, err := databasequalification.LoadFailoverObservation(
		evidence.FailoverObservationPath)
	if err != nil {
		fail("managed database failover observation rejected")
	}
	requireLive := !failover.DevelopmentOnly
	if requireLive && !*acknowledge {
		fail("live managed database qualification acknowledgement is required")
	}
	if requireLive {
		evidence, _, err = databasequalification.LoadDatabaseEvidenceManifest(
			*manifestPath, true)
		if err != nil {
			fail("live managed database evidence manifest rejected")
		}
	}
	receipt, err := databasequalification.BuildDatabaseReceipt(evidence)
	if err != nil {
		fail("managed database qualification evidence rejected")
	}
	payload, err := databasequalification.SignDatabaseReceipt(receipt,
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("managed database qualification receipt signing failed")
	}
	if err := databasequalification.WriteNew(*outputPath, payload); err != nil {
		fail("managed database qualification receipt publication failed")
	}
	fmt.Printf("%s: %s\n", receipt.Result, *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
