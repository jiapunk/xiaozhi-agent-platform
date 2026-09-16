package accountauth

import (
	"context"
	"fmt"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type TokenPurpose string

const (
	PurposeClaim                      TokenPurpose = "claim"
	PurposeRelease                    TokenPurpose = "release"
	PurposeActionConsent              TokenPurpose = "action-consent"
	MaximumActionConsentTokenLifetime              = 5 * time.Minute
)

type IssuedToken struct {
	Bearer        string
	Claims        auth.Claims
	Authorization Authorization
}

// Service is called by a product-selected IdP/BFF adapter after it validates
// the user and tenant. It deliberately does not implement passwords, passkeys,
// OAuth callbacks or MFA policy.
type Service struct {
	issuer *auth.CompanionJWTIssuer
	ledger Ledger
}

func NewService(issuer *auth.CompanionJWTIssuer,
	ledger Ledger) (*Service, error) {
	if issuer == nil || ledger == nil {
		return nil, fmt.Errorf("invalid Companion authorization service configuration")
	}
	return &Service{issuer: issuer, ledger: ledger}, nil
}

// BeginAuthenticatedSession must be invoked only after the external IdP
// adapter authenticates this exact principal. The returned revision is an
// issuance precondition, not a login credential.
func (service *Service) BeginAuthenticatedSession(ctx context.Context,
	principal Principal) (Session, error) {
	if service == nil || service.ledger == nil {
		return Session{}, ErrUnavailable
	}
	return service.ledger.BeginAuthenticatedSession(ctx, principal)
}

// Issue signs first but publishes the bearer only after its JTI is durably
// registered at the exact session revision. If persistence fails, the signed
// value remains local and is never returned to the caller.
func (service *Service) Issue(ctx context.Context, session Session,
	purpose TokenPurpose, deviceID string) (IssuedToken, error) {
	if service == nil || service.issuer == nil || service.ledger == nil ||
		ctx == nil || !ValidSession(session) {
		return IssuedToken{}, ErrInvalid
	}
	var (
		bearer string
		claims auth.Claims
		err    error
	)
	switch purpose {
	case PurposeClaim:
		if deviceID != "" {
			return IssuedToken{}, ErrInvalid
		}
		bearer, claims, err = service.issuer.Issue(
			session.Principal.Subject, session.Principal.TenantID)
	case PurposeRelease:
		bearer, claims, err = service.issuer.IssueRelease(
			session.Principal.Subject, session.Principal.TenantID, deviceID)
	case PurposeActionConsent:
		bearer, claims, err = service.issuer.IssueActionConsent(
			session.Principal.Subject, session.Principal.TenantID, deviceID)
	default:
		return IssuedToken{}, ErrInvalid
	}
	if err != nil {
		return IssuedToken{}, fmt.Errorf("issue Companion JWT: %w", err)
	}
	if purpose == PurposeActionConsent &&
		time.Duration(claims.Expires-claims.IssuedAt)*time.Second >
			MaximumActionConsentTokenLifetime {
		return IssuedToken{}, ErrInvalid
	}
	binding, err := BindingFromClaims(claims)
	if err != nil {
		return IssuedToken{}, err
	}
	authorization, err := service.ledger.RegisterToken(ctx, session, binding)
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Bearer: bearer, Claims: claims,
		Authorization: authorization}, nil
}

func (service *Service) Logout(ctx context.Context,
	session Session) (Account, error) {
	if service == nil || service.ledger == nil {
		return Account{}, ErrUnavailable
	}
	return service.ledger.Logout(ctx, session)
}

// Suspend and Resume are administrative lifecycle hooks. The selected IdP or
// account-risk adapter must authorize these calls; this package supplies only
// their durable revision semantics.
func (service *Service) Suspend(ctx context.Context,
	principal Principal) (Account, error) {
	if service == nil || service.ledger == nil {
		return Account{}, ErrUnavailable
	}
	return service.ledger.Suspend(ctx, principal)
}

func (service *Service) Resume(ctx context.Context,
	principal Principal) (Account, error) {
	if service == nil || service.ledger == nil {
		return Account{}, ErrUnavailable
	}
	return service.ledger.Resume(ctx, principal)
}

func (service *Service) RevokeToken(ctx context.Context, principal Principal,
	tokenID string) error {
	if service == nil || service.ledger == nil {
		return ErrUnavailable
	}
	return service.ledger.RevokeToken(ctx, principal, tokenID)
}
