package accountauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

func accountFixture(t *testing.T) (*Store, *Service, Principal) {
	t.Helper()
	store, err := NewStore(1024)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("account-authorization-test-key"))
	issuer, err := auth.NewCompanionJWTIssuer(
		ed25519.NewKeyFromSeed(seed[:]), "account-key-1",
		"https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(issuer, store)
	if err != nil {
		t.Fatal(err)
	}
	return store, service,
		Principal{TenantID: "tenant-1", Subject: "user-1"}
}

func TestIssueRegistersExactJTIWithoutRawBearer(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, err := service.BeginAuthenticatedSession(
		context.Background(), principal)
	if err != nil || session.AccountRevision != 1 {
		t.Fatalf("begin session: %#v %v", session, err)
	}
	tests := []struct {
		purpose  TokenPurpose
		deviceID string
		action   string
	}{
		{PurposeClaim, "", auth.CompanionClaimAction},
		{PurposeRelease, "device-1", auth.CompanionReleaseAction},
		{PurposeActionConsent, "device-1", auth.CompanionConsentAction},
	}
	seen := make(map[string]bool)
	for _, testCase := range tests {
		issued, issueErr := service.Issue(context.Background(), session,
			testCase.purpose, testCase.deviceID)
		if issueErr != nil || issued.Bearer == "" ||
			issued.Claims.Action != testCase.action ||
			issued.Claims.DeviceID != testCase.deviceID ||
			issued.Authorization.AccountRevision != 1 {
			t.Fatalf("issue %s: %#v %v", testCase.purpose, issued, issueErr)
		}
		if seen[issued.Claims.TokenID] {
			t.Fatal("duplicate JTI")
		}
		seen[issued.Claims.TokenID] = true
		binding, bindingErr := BindingFromClaims(issued.Claims)
		if bindingErr != nil {
			t.Fatal(bindingErr)
		}
		authorization, active, introspectionErr := store.Introspect(
			context.Background(), binding)
		if introspectionErr != nil || !active ||
			authorization != issued.Authorization {
			t.Fatalf("introspection: %#v active=%t err=%v",
				authorization, active, introspectionErr)
		}
		if strings.Contains(fmt.Sprintf("%#v", store.tokens), issued.Bearer) {
			t.Fatal("raw JWT crossed the ledger boundary")
		}
	}
}

func TestLogoutIsAnIssuanceFenceAndNewSessionUsesNewRevision(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, err := service.BeginAuthenticatedSession(
		context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(context.Background(), session,
		PurposeActionConsent, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	account, err := service.Logout(context.Background(), session)
	if err != nil || account.Revision != 2 || account.Status != AccountActive {
		t.Fatalf("logout: %#v %v", account, err)
	}
	binding, _ := BindingFromClaims(issued.Claims)
	if _, active, err := store.Introspect(context.Background(), binding); err != nil || active {
		t.Fatalf("logged-out token active=%t err=%v", active, err)
	}
	if leaked, err := service.Issue(context.Background(), session,
		PurposeClaim, ""); !errors.Is(err, ErrStaleSession) || leaked != (IssuedToken{}) {
		t.Fatalf("stale issuance: %#v %v", leaked, err)
	}
	if _, err := service.Logout(context.Background(), session); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("logout replay: %v", err)
	}
	newSession, err := service.BeginAuthenticatedSession(
		context.Background(), principal)
	if err != nil || newSession.AccountRevision != 2 {
		t.Fatalf("new session: %#v %v", newSession, err)
	}
	newToken, err := service.Issue(context.Background(), newSession,
		PurposeClaim, "")
	if err != nil {
		t.Fatal(err)
	}
	newBinding, _ := BindingFromClaims(newToken.Claims)
	if _, active, err := store.Introspect(context.Background(), newBinding); err != nil || !active {
		t.Fatalf("new revision active=%t err=%v", active, err)
	}
}

func TestSuspensionResumeAndExactTokenRevocation(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, err := service.BeginAuthenticatedSession(
		context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Issue(context.Background(), session,
		PurposeRelease, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Issue(context.Background(), session,
		PurposeRelease, "device-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeToken(context.Background(), principal,
		first.Claims.TokenID); err != nil {
		t.Fatal(err)
	}
	firstBinding, _ := BindingFromClaims(first.Claims)
	secondBinding, _ := BindingFromClaims(second.Claims)
	if _, active, _ := store.Introspect(context.Background(), firstBinding); active {
		t.Fatal("revoked JTI remained active")
	}
	if _, active, _ := store.Introspect(context.Background(), secondBinding); !active {
		t.Fatal("sibling JTI was revoked")
	}
	suspended, err := service.Suspend(context.Background(), principal)
	if err != nil || suspended.Status != AccountSuspended || suspended.Revision != 2 {
		t.Fatalf("suspend: %#v %v", suspended, err)
	}
	if _, err := service.BeginAuthenticatedSession(context.Background(), principal); !errors.Is(err, ErrSuspended) {
		t.Fatalf("suspended sign-in: %v", err)
	}
	if _, active, _ := store.Introspect(context.Background(), secondBinding); active {
		t.Fatal("suspended account token remained active")
	}
	resumed, err := service.Resume(context.Background(), principal)
	if err != nil || resumed.Status != AccountActive || resumed.Revision != 3 {
		t.Fatalf("resume: %#v %v", resumed, err)
	}
	newSession, err := service.BeginAuthenticatedSession(
		context.Background(), principal)
	if err != nil || newSession.AccountRevision != 3 {
		t.Fatalf("resumed session: %#v %v", newSession, err)
	}
	if _, active, _ := store.Introspect(context.Background(), secondBinding); active {
		t.Fatal("resume reactivated an old token")
	}
}

func TestExactBindingMutationsAreInactive(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	issued, err := service.Issue(context.Background(), session,
		PurposeActionConsent, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := BindingFromClaims(issued.Claims)
	mutations := []func(*TokenBinding){
		func(value *TokenBinding) { value.Subject = "user-2" },
		func(value *TokenBinding) { value.TenantID = "tenant-2" },
		func(value *TokenBinding) { value.Action = auth.CompanionReleaseAction },
		func(value *TokenBinding) { value.DeviceID = "device-2" },
		func(value *TokenBinding) { value.IssuedAt-- },
		func(value *TokenBinding) { value.ExpiresAt-- },
	}
	for index, mutate := range mutations {
		mutated := binding
		mutate(&mutated)
		if _, active, introspectionErr := store.Introspect(
			context.Background(), mutated); introspectionErr != nil || active {
			t.Fatalf("mutation %d active=%t err=%v", index, active,
				introspectionErr)
		}
	}
}

func TestConcurrentLogoutLeavesNoOldRevisionTokenActive(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	start := make(chan struct{})
	var group sync.WaitGroup
	var mutex sync.Mutex
	bindings := make([]TokenBinding, 0, 64)
	for index := 0; index < 64; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			issued, err := service.Issue(context.Background(), session,
				PurposeClaim, "")
			if err == nil {
				binding, _ := BindingFromClaims(issued.Claims)
				mutex.Lock()
				bindings = append(bindings, binding)
				mutex.Unlock()
			} else if !errors.Is(err, ErrStaleSession) {
				t.Errorf("concurrent issue: %v", err)
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		if _, err := service.Logout(context.Background(), session); err != nil {
			t.Errorf("concurrent logout: %v", err)
		}
	}()
	close(start)
	group.Wait()
	for _, binding := range bindings {
		if _, active, err := store.Introspect(context.Background(), binding); err != nil || active {
			t.Fatalf("old-revision token survived: active=%t err=%v", active, err)
		}
	}
}

type rejectingLedger struct {
	Ledger
}

func (rejectingLedger) RegisterToken(context.Context, Session,
	TokenBinding) (Authorization, error) {
	return Authorization{}, ErrUnavailable
}

func TestIssueNeverReturnsBearerWhenLedgerRejectsPublication(t *testing.T) {
	store, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	blocked, err := NewService(service.issuer, rejectingLedger{Ledger: store})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := blocked.Issue(context.Background(), session,
		PurposeClaim, "")
	if !errors.Is(err, ErrUnavailable) || issued != (IssuedToken{}) {
		t.Fatalf("failed publication leaked bearer: %#v %v", issued, err)
	}
}

func TestValidationAndReferenceCapacityFailClosed(t *testing.T) {
	if _, err := NewStore(0); err == nil {
		t.Fatal("zero reference capacity accepted")
	}
	if _, err := NewService(nil, nil); err == nil {
		t.Fatal("nil service dependencies accepted")
	}
	for _, binding := range []TokenBinding{
		{},
		{TokenID: "token-1", Subject: "user-1", TenantID: "tenant-1",
			Action: auth.CompanionClaimAction, DeviceID: "device-1",
			IssuedAt: 1, ExpiresAt: 61},
		{TokenID: "token-1", Subject: "user-1", TenantID: "tenant-1",
			Action: "admin", IssuedAt: 1, ExpiresAt: 61},
	} {
		if ValidTokenBinding(binding) {
			t.Fatalf("invalid binding accepted: %#v", binding)
		}
	}
	_, service, principal := accountFixture(t)
	session, _ := service.BeginAuthenticatedSession(context.Background(), principal)
	issued, err := service.Issue(context.Background(), session, PurposeClaim, "")
	if err != nil {
		t.Fatal(err)
	}
	claims := issued.Claims
	claims.Issuer = ""
	if _, err := BindingFromClaims(claims); !errors.Is(err, ErrInvalid) {
		t.Fatalf("issuer-less Companion claims accepted: %v", err)
	}
}
