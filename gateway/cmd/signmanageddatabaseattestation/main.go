package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/databasequalification"
)

func main() {
	failoverPath := flag.String("failover-observation", "", "canonical M73 failover observation")
	restorePath := flag.String("restore-observation", "", "canonical M73 restore observation")
	auditPath := flag.String("provider-audit-evidence", "", "canonical managed provider audit evidence")
	verifiedText := flag.String("verified-at", "", "trusted RFC3339 audit verification time")
	expiresText := flag.String("expires-at", "", "RFC3339 expiry within 24 hours")
	privateKeyPath := flag.String("signing-private-key", "", "database audit authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "database audit authority key ID")
	outputPath := flag.String("output", "", "new signed managed database attestation")
	acknowledge := flag.Bool("acknowledge-live-managed-database-provider-audit", false,
		"acknowledge managed control-plane, backup, restore, encryption and WORM verification")
	flag.Parse()
	if flag.NArg() != 0 || *failoverPath == "" || *restorePath == "" ||
		*auditPath == "" || *verifiedText == "" || *expiresText == "" ||
		*privateKeyPath == "" || *signingKeyID == "" || *outputPath == "" {
		fail("complete managed database attestation arguments are required")
	}
	failover, failoverPayload, err := databasequalification.LoadFailoverObservation(*failoverPath)
	if err != nil {
		fail("managed database failover observation rejected")
	}
	restore, restorePayload, err := databasequalification.LoadRestoreObservation(*restorePath)
	if err != nil {
		fail("managed database restore observation rejected")
	}
	audit, auditPayload, err := databasequalification.LoadAuditDocument(*auditPath)
	if err != nil {
		fail("managed database provider audit evidence rejected")
	}
	if !audit.DevelopmentOnly && !*acknowledge {
		fail("live managed database provider audit acknowledgement is required")
	}
	verified := parseTime(*verifiedText, "managed database verification time rejected")
	expires := parseTime(*expiresText, "managed database attestation expiry rejected")
	payload, err := databasequalification.SignDatabaseAttestation(
		databasequalification.DatabaseAttestationInput{
			Failover: failover, Restore: restore,
			FailoverObservationSHA256: databasequalification.DigestPayload(failoverPayload),
			RestoreObservationSHA256:  databasequalification.DigestPayload(restorePayload),
			Audit:                     audit, ProviderAuditSHA256: databasequalification.DigestPayload(auditPayload),
			VerifiedAt: verified, ExpiresAt: expires},
		*privateKeyPath, *signingKeyID)
	if err != nil {
		fail("managed database attestation signing failed")
	}
	if err := databasequalification.WriteNew(*outputPath, payload); err != nil {
		fail("managed database attestation publication failed")
	}
	fmt.Printf("managed database attestation: %s\n", *outputPath)
}

func parseTime(value, message string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || parsed.Nanosecond() != 0 {
		fail(message)
	}
	return parsed
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
