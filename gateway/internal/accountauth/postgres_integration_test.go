package accountauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

func TestPostgresCompanionAuthorizationIntegration(t *testing.T) {
	databaseURL := os.Getenv("ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	rawSchema := make([]byte, 8)
	if _, err := rand.Read(rawSchema); err != nil {
		t.Fatal(err)
	}
	schema := "xz_account_auth_test_" + hex.EncodeToString(rawSchema)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(
			context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupContext,
			"DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	}()

	migrations := make([][]byte, 0, 3)
	for _, name := range []string{"0001_companion_authorization.sql",
		"0002_companion_push_installations.sql",
		"0004_service_entitlements.sql"} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations",
			"account", name))
		if err != nil {
			t.Fatal(err)
		}
		migrations = append(migrations, migration)
	}
	migrationConfig := adminConfig.Copy()
	migrationConfig.RuntimeParams["search_path"] = schema
	migrationConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	migrationConnection, err := pgx.ConnectConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if _, err := migrationConnection.Exec(ctx, string(migration)); err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatal(err)
		}
	}
	if err := migrationConnection.Close(ctx); err != nil {
		t.Fatal(err)
	}

	openDatabase := func() *sql.DB {
		config := adminConfig.Copy()
		config.RuntimeParams["search_path"] = schema
		database := stdlib.OpenDB(*config)
		database.SetMaxOpenConns(16)
		database.SetMaxIdleConns(4)
		t.Cleanup(func() { _ = database.Close() })
		return database
	}
	storeA, err := NewPostgresStore(openDatabase(), 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	storeB, err := NewPostgresStore(openDatabase(), 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.VerifySchema(); err != nil {
		t.Fatal(err)
	}

	seed := sha256.Sum256([]byte("postgres-account-authorization-test-key"))
	issuer, err := auth.NewCompanionJWTIssuer(
		ed25519.NewKeyFromSeed(seed[:]), "account-key-1",
		"https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serviceA, _ := NewService(issuer, storeA)
	serviceB, _ := NewService(issuer, storeB)
	principal := Principal{TenantID: "tenant-1", Subject: "user-1"}
	session, err := serviceA.BeginAuthenticatedSession(ctx, principal)
	if err != nil || session.AccountRevision != 1 {
		t.Fatalf("begin session: %#v %v", session, err)
	}
	entitlementUpdate := entitlementUpdate(principal, "postgres-billing-event-1",
		0, 1, EntitlementActive, true, true,
		time.Now().UTC().Truncate(time.Second).Add(time.Hour))
	entitlement, applied, err := storeA.ApplyServiceEntitlement(ctx,
		entitlementUpdate)
	if err != nil || !applied || entitlement.Revision != 1 {
		t.Fatalf("apply entitlement: %#v applied=%t err=%v",
			entitlement, applied, err)
	}
	grant, allowed, err := storeB.AuthorizeService(ctx, principal,
		ProductServiceAgent)
	if err != nil || !allowed || grant.Revision != 1 {
		t.Fatalf("cross-replica entitlement: %#v allowed=%t err=%v",
			grant, allowed, err)
	}
	if _, replayApplied, err := storeB.ApplyServiceEntitlement(ctx,
		entitlementUpdate); err != nil || replayApplied {
		t.Fatalf("entitlement replay applied=%t err=%v", replayApplied, err)
	}
	installationRegistration := PushInstallationRegistration{
		InstallationID: pushInstallationID(1), Platform: PushPlatformFCM,
		Token: protectedPushToken("postgres-a"),
	}
	firstInstallation, err := storeA.UpsertPushInstallation(ctx, session,
		installationRegistration)
	if err != nil {
		t.Fatalf("register installation: %v", err)
	}
	installations, err := storeB.ActivePushInstallations(ctx, principal)
	if err != nil || len(installations) != 1 ||
		installations[0].InstallationID != firstInstallation.InstallationID {
		t.Fatalf("cross-replica installation: %#v %v", installations, err)
	}
	oldDigest := firstInstallation.Token.Digest
	installationRegistration.Token = protectedPushToken("postgres-b")
	rotatedInstallation, err := storeB.UpsertPushInstallation(ctx, session,
		installationRegistration)
	if err != nil {
		t.Fatalf("rotate installation: %v", err)
	}
	if err := storeA.InvalidatePushInstallation(ctx, principal,
		rotatedInstallation.InstallationID, oldDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale provider response removed rotated installation: %v", err)
	}
	installations, err = storeA.ActivePushInstallations(ctx, principal)
	if err != nil || len(installations) != 1 ||
		installations[0].Token.Digest != rotatedInstallation.Token.Digest {
		t.Fatalf("rotated installation unavailable: %#v %v", installations, err)
	}
	issued, err := serviceA.Issue(ctx, session,
		PurposeActionConsent, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := BindingFromClaims(issued.Claims)
	authorization, active, err := storeB.Introspect(ctx, binding)
	if err != nil || !active || authorization != issued.Authorization {
		t.Fatalf("cross-replica introspection: %#v active=%t err=%v",
			authorization, active, err)
	}
	var rawBearerMatches int
	if err := storeB.db.QueryRowContext(ctx, `
SELECT count(*) FROM companion_tokens
WHERE token_id = $1 OR subject = $1 OR tenant_id = $1 OR action = $1 OR device_id = $1`,
		issued.Bearer).Scan(&rawBearerMatches); err != nil {
		t.Fatal(err)
	}
	if rawBearerMatches != 0 {
		t.Fatal("raw JWT crossed the PostgreSQL ledger boundary")
	}

	account, err := serviceB.Logout(ctx, session)
	if err != nil || account.Revision != 2 {
		t.Fatalf("cross-replica logout: %#v %v", account, err)
	}
	if _, active, err := storeA.Introspect(ctx, binding); err != nil || active {
		t.Fatalf("logged-out token active=%t err=%v", active, err)
	}
	installations, err = storeA.ActivePushInstallations(ctx, principal)
	if err != nil || len(installations) != 0 {
		t.Fatalf("logout left installation active: %#v %v", installations, err)
	}
	if leaked, err := serviceA.Issue(ctx, session, PurposeClaim, ""); !errors.Is(err, ErrStaleSession) || leaked != (IssuedToken{}) {
		t.Fatalf("stale post-logout issue: %#v %v", leaked, err)
	}
	newSession, err := serviceB.BeginAuthenticatedSession(ctx, principal)
	if err != nil || newSession.AccountRevision != 2 {
		t.Fatalf("new session: %#v %v", newSession, err)
	}

	base := TokenBinding{
		TokenID: "exact-race-token", Subject: principal.Subject,
		TenantID: principal.TenantID, Action: auth.CompanionClaimAction,
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	}
	var winners atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			store := storeA
			if index%2 != 0 {
				store = storeB
			}
			if _, err := store.RegisterToken(ctx, newSession, base); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("duplicate JTI race: %v", err)
			}
		}(index)
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("duplicate JTI winners=%d, want 1", winners.Load())
	}

	started := make(chan struct{})
	bindings := make([]TokenBinding, 0, 32)
	var bindingsMutex sync.Mutex
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-started
			service := serviceA
			if index%2 != 0 {
				service = serviceB
			}
			issued, err := service.Issue(ctx, newSession, PurposeClaim, "")
			if err == nil {
				binding, _ := BindingFromClaims(issued.Claims)
				bindingsMutex.Lock()
				bindings = append(bindings, binding)
				bindingsMutex.Unlock()
			} else if !errors.Is(err, ErrStaleSession) {
				t.Errorf("issuance/logout race: %v", err)
			}
		}(index)
	}
	group.Add(1)
	go func() {
		defer group.Done()
		<-started
		if _, err := serviceB.Logout(ctx, newSession); err != nil {
			t.Errorf("race logout: %v", err)
		}
	}()
	close(started)
	group.Wait()
	for _, candidate := range bindings {
		if _, active, err := storeA.Introspect(ctx, candidate); err != nil || active {
			t.Fatalf("race token active=%t err=%v", active, err)
		}
	}

	latest, err := serviceA.BeginAuthenticatedSession(ctx, principal)
	if err != nil || latest.AccountRevision != 3 {
		t.Fatalf("latest session: %#v %v", latest, err)
	}
	if suspended, err := storeB.Suspend(ctx, principal); err != nil ||
		suspended.Status != AccountSuspended || suspended.Revision != 4 {
		t.Fatalf("suspend: %#v %v", suspended, err)
	}
	if _, err := serviceA.BeginAuthenticatedSession(ctx, principal); !errors.Is(err, ErrSuspended) {
		t.Fatalf("suspended account session: %v", err)
	}
	if resumed, err := storeA.Resume(ctx, principal); err != nil ||
		resumed.Status != AccountActive || resumed.Revision != 5 {
		t.Fatalf("resume: %#v %v", resumed, err)
	}
	if err := storeB.PruneExpired(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
}
