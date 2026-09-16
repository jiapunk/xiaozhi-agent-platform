package pushdelivery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type OAuthAccessToken struct {
	Value     string
	ExpiresAt time.Time
}

type OAuthAccessTokenSource interface {
	AccessToken(context.Context) (OAuthAccessToken, error)
}

type CachedOAuthBearerProvider struct {
	source OAuthAccessTokenSource
	now    func() time.Time

	mu    sync.Mutex
	token OAuthAccessToken
}

var _ BearerTokenProvider = (*CachedOAuthBearerProvider)(nil)

func NewCachedOAuthBearerProvider(source OAuthAccessTokenSource) (
	*CachedOAuthBearerProvider, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	return &CachedOAuthBearerProvider{source: source, now: time.Now}, nil
}

func (provider *CachedOAuthBearerProvider) BearerToken(ctx context.Context) (
	string, error) {
	if provider == nil || provider.source == nil || ctx == nil {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: OAuth token context", ErrUnavailable)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	now := provider.now().UTC()
	if validOAuthAccessToken(provider.token, now) &&
		provider.token.ExpiresAt.After(now.Add(5*time.Minute)) {
		return provider.token.Value, nil
	}
	refreshed, err := provider.source.AccessToken(ctx)
	if err != nil || !validOAuthAccessToken(refreshed, now) {
		if validOAuthAccessToken(provider.token, now) &&
			provider.token.ExpiresAt.After(now.Add(30*time.Second)) {
			return provider.token.Value, nil
		}
		if errors.Is(err, ErrCredentialRejected) {
			return "", fmt.Errorf("%w: OAuth token refresh", err)
		}
		return "", fmt.Errorf("%w: OAuth token refresh", ErrUnavailable)
	}
	provider.token = refreshed
	return refreshed.Value, nil
}

func validOAuthAccessToken(token OAuthAccessToken, now time.Time) bool {
	lifetime := token.ExpiresAt.Sub(now)
	return validBearer(token.Value) && lifetime > 0 && lifetime <= 2*time.Hour
}
