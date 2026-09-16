package pushdelivery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type oauthSourceStub struct {
	mu    sync.Mutex
	token OAuthAccessToken
	err   error
	calls int
}

func TestCachedOAuthBearerPreservesExplicitCredentialRejectionWithoutFallback(t *testing.T) {
	source := &oauthSourceStub{err: fmt.Errorf("%w: %w",
		ErrUnavailable, ErrCredentialRejected)}
	provider, err := NewCachedOAuthBearerProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.BearerToken(context.Background()); !errors.Is(err, ErrCredentialRejected) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("credential rejection was erased: %v", err)
	}
}

func (source *oauthSourceStub) AccessToken(context.Context) (
	OAuthAccessToken, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	return source.token, source.err
}

func TestCachedOAuthBearerProviderRefreshesAndUsesShortFallback(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	source := &oauthSourceStub{token: OAuthAccessToken{
		Value: "first-access-token", ExpiresAt: now.Add(time.Hour)}}
	provider, err := NewCachedOAuthBearerProvider(source)
	if err != nil {
		t.Fatal(err)
	}
	provider.now = func() time.Time { return now }
	first, err := provider.BearerToken(context.Background())
	if err != nil || first != "first-access-token" || source.calls != 1 {
		t.Fatalf("first=%q calls=%d err=%v", first, source.calls, err)
	}
	if cached, cacheErr := provider.BearerToken(context.Background()); cacheErr != nil || cached != first || source.calls != 1 {
		t.Fatalf("cached=%q calls=%d err=%v", cached, source.calls, cacheErr)
	}
	now = now.Add(56 * time.Minute)
	source.err = errors.New("OAuth unavailable")
	if fallback, fallbackErr := provider.BearerToken(context.Background()); fallbackErr != nil || fallback != first || source.calls != 2 {
		t.Fatalf("fallback=%q calls=%d err=%v", fallback, source.calls, fallbackErr)
	}
	now = now.Add(4*time.Minute - 30*time.Second)
	if _, expiredErr := provider.BearerToken(context.Background()); !errors.Is(expiredErr, ErrUnavailable) {
		t.Fatalf("expired fallback err=%v", expiredErr)
	}
}

func TestCachedOAuthBearerProviderRejectsInvalidRefresh(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	source := &oauthSourceStub{token: OAuthAccessToken{
		Value: "otherwise-valid-token", ExpiresAt: now.Add(3 * time.Hour)}}
	provider, _ := NewCachedOAuthBearerProvider(source)
	provider.now = func() time.Time { return now }
	if _, err := provider.BearerToken(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("long-lived token err=%v", err)
	}
}
