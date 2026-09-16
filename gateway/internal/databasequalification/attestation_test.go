package databasequalification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedDatabaseFixtureCannotSatisfyLiveVerifier(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
	failoverConfig := testFailoverConfig(clock)
	failover, err := (&Runner{now: clock.now, pause: clock.pause}).
		RunFailover(context.Background(), failoverConfig)
	if err != nil {
		t.Fatal(err)
	}
	failoverPayload, _ := CanonicalFailoverObservation(failover)
	marker, _ := parseCanonicalTime(failover.Databases[0].RestoreMarkerCommittedAt)
	exclusion, _ := parseCanonicalTime(failover.Databases[0].RestoreExclusionCommittedAt)
	clock.current = clock.current.Add(time.Second)
	restoreConfig := RestoreRunConfig{QualificationID: failover.QualificationID,
		Environment: "staging", DevelopmentOnly: true,
		ConfigSHA256: strings.Repeat("c", 64), ToolSHA256: strings.Repeat("d", 64),
		FailoverObservationSHA256: digestBytes(failoverPayload),
		RunBindingSHA256:          failover.RunBindingSHA256,
		Nonce:                     append([]byte(nil), failoverConfig.Nonce...),
		Candidates:                make([]RestoreDatabaseCandidate, 0, len(ExactRoles))}
	for index, role := range ExactRoles {
		store := &fakeEventStore{role: role, clock: clock,
			beforeBinding: strings.Repeat(string(rune('6'+index)), 64),
			afterBinding:  strings.Repeat(string(rune('9'+index)), 64),
			failoverAt:    clock.current.Add(time.Hour)}
		store.events = []Event{
			{Sequence: 1, Phase: PhasePre,
				PayloadSHA256: eventPayloadSHA256(failover.RunBindingSHA256,
					role, 1, PhasePre), CommittedAt: marker.Add(-time.Second)},
			{Sequence: 2, Phase: PhaseRestoreMarker,
				PayloadSHA256: eventPayloadSHA256(failover.RunBindingSHA256,
					role, 2, PhaseRestoreMarker), CommittedAt: marker},
		}
		restoreConfig.Candidates = append(restoreConfig.Candidates,
			RestoreDatabaseCandidate{Role: role,
				ManagedClusterID:               failover.Databases[index].ManagedClusterID,
				RestoreOperationID:             "fixture-restore-operation-" + string(rune('1'+index)),
				RequestedRecoveryTarget:        marker.Add(2 * time.Second),
				SourceEndpointAuthoritySHA256:  failover.Databases[index].EndpointAuthoritySHA256,
				RestoreEndpointAuthoritySHA256: strings.Repeat(string(rune('c'+index)), 64),
				MarkerCommittedAt:              marker, ExclusionCommittedAt: exclusion, Store: store})
	}
	restore, err := (&Runner{now: clock.now, pause: clock.pause}).
		RunRestore(context.Background(), restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	restorePayload, _ := CanonicalRestoreObservation(restore)
	ready, _ := parseCanonicalTime(failover.ReadyAt)
	failoverFinished, _ := parseCanonicalTime(failover.FinishedAt)
	restoreFinished, _ := parseCanonicalTime(restore.FinishedAt)
	audit := AuditDocument{Schema: 1, QualificationID: failover.QualificationID,
		Environment: "staging", DevelopmentOnly: true, Provider: FixtureAuditProvider,
		WORMRecordID: "fixture-worm-record", FailoverStartedAt: ready.Format(time.RFC3339),
		FailoverCompletedAt: failoverFinished.Format(time.RFC3339),
		RestoreCompletedAt:  restoreFinished.Format(time.RFC3339),
		RPOTargetSeconds:    300, RTOTargetSeconds: 300,
		Databases: make([]DatabaseAuditBinding, 0, len(ExactRoles))}
	for index, role := range ExactRoles {
		audit.Databases = append(audit.Databases, DatabaseAuditBinding{Role: role,
			ManagedClusterID:        failover.Databases[index].ManagedClusterID,
			FailoverOperationID:     "fixture-failover-operation-" + string(rune('1'+index)),
			AutomatedBackupID:       "fixture-backup-" + string(rune('1'+index)),
			RestoreOperationID:      restore.Databases[index].RestoreOperationID,
			RequestedRecoveryTarget: restore.Databases[index].RequestedRecoveryTarget,
			FailoverRTOSeconds:      2, RestoreRTOSeconds: 1})
	}
	privatePath, publicPath := databaseTestKeyPair(t)
	verified := restoreFinished.Add(time.Second)
	payload, err := SignDatabaseAttestation(DatabaseAttestationInput{
		Failover: failover, Restore: restore,
		FailoverObservationSHA256: digestBytes(failoverPayload),
		RestoreObservationSHA256:  digestBytes(restorePayload), Audit: audit,
		ProviderAuditSHA256: strings.Repeat("e", 64), VerifiedAt: verified,
		ExpiresAt: verified.Add(time.Hour)}, privatePath, "m73-fixture-audit-key")
	if err != nil {
		t.Fatal(err)
	}
	options := DatabaseAttestationVerifyOptions{TrustedPublicKey: publicPath,
		ExpectedSigningKeyID:        "m73-fixture-audit-key",
		ExpectedProvider:            FixtureAuditProvider,
		ExpectedProviderAuditSHA256: strings.Repeat("e", 64), EvaluationTime: verified}
	attestation, err := VerifyDatabaseAttestation(payload, options)
	if err != nil || !attestation.DevelopmentOnly {
		t.Fatalf("fixture attestation rejected: %v", err)
	}
	options.RequireLive = true
	if _, err := VerifyDatabaseAttestation(payload, options); err == nil {
		t.Fatal("fixture database attestation satisfied live verifier")
	}
	tampered := strings.Replace(string(payload), FixtureDatabaseAttestationResult,
		LiveDatabaseAttestationResult, 1)
	options.RequireLive = false
	if _, err := VerifyDatabaseAttestation([]byte(tampered), options); err == nil {
		t.Fatal("tampered database attestation retained authority")
	}
}

func databaseTestKeyPair(t *testing.T) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	publicDER, _ := x509.MarshalPKIXPublicKey(public)
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER}), 0o444); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}
