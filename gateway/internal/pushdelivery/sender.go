package pushdelivery

import (
	"bytes"
	"context"
	"errors"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
)

type WakeSender struct {
	installations accountauth.PushInstallationStore
	protector     accountauth.PushTokenProtector
	providers     map[accountauth.PushPlatform]Provider
}

var _ actionconsent.WakeSender = (*WakeSender)(nil)

func NewWakeSender(installations accountauth.PushInstallationStore,
	protector accountauth.PushTokenProtector,
	providers map[accountauth.PushPlatform]Provider) (*WakeSender, error) {
	if installations == nil || protector == nil || len(providers) < 1 ||
		len(providers) > 3 {
		return nil, ErrInvalid
	}
	copyProviders := make(map[accountauth.PushPlatform]Provider, len(providers))
	for platform, provider := range providers {
		if !accountauth.ValidPushPlatform(platform) || provider == nil {
			return nil, ErrInvalid
		}
		copyProviders[platform] = provider
	}
	return &WakeSender{installations: installations, protector: protector,
		providers: copyProviders}, nil
}

func (sender *WakeSender) SendWake(ctx context.Context,
	actor actionconsent.Actor, contract string,
	payload []byte) (actionconsent.WakeSendDisposition, error) {
	if sender == nil || ctx == nil || sender.installations == nil ||
		sender.protector == nil || actor.OwnerID == "" || actor.TenantID == "" ||
		actor.DeviceID == "" || actor.OwnerRevision == 0 ||
		contract != actionconsent.WakeContract ||
		!bytes.Equal(payload, actionconsent.CanonicalWakePayload()) {
		return actionconsent.WakeSendRetry, ErrInvalid
	}
	principal := accountauth.Principal{TenantID: actor.TenantID,
		Subject: actor.OwnerID}
	installations, err := sender.installations.ActivePushInstallations(ctx,
		principal)
	if err != nil {
		return actionconsent.WakeSendRetry, ErrUnavailable
	}
	if len(installations) == 0 {
		return actionconsent.WakeSendNoInstallation, nil
	}
	accepted := false
	retry := false
	type providerResult struct {
		installation accountauth.PushInstallation
		result       DeliveryResult
		err          error
	}
	results := make(chan providerResult, len(installations))
	pending := 0
	for _, installation := range installations {
		provider := sender.providers[installation.Platform]
		if provider == nil {
			retry = true
			continue
		}
		binding := accountauth.PushTokenBinding{Principal: principal,
			InstallationID: installation.InstallationID,
			Platform:       installation.Platform}
		rawToken, err := sender.protector.Open(ctx, binding,
			installation.Token)
		if err != nil {
			retry = true
			continue
		}
		pending++
		go func(installation accountauth.PushInstallation, provider Provider,
			rawToken string) {
			result, sendErr := provider.Send(ctx, rawToken)
			results <- providerResult{installation: installation,
				result: result, err: sendErr}
		}(installation, provider, rawToken)
	}
	for index := 0; index < pending; index++ {
		delivery := <-results
		switch delivery.result {
		case DeliveryAccepted:
			if delivery.err == nil {
				accepted = true
			} else {
				retry = true
			}
		case DeliveryInvalidInstallation:
			if delivery.err != nil {
				retry = true
				continue
			}
			if err := sender.installations.InvalidatePushInstallation(ctx,
				principal, delivery.installation.InstallationID,
				delivery.installation.Token.Digest); err != nil &&
				!errors.Is(err, accountauth.ErrNotFound) {
				retry = true
			}
		case DeliveryRetry:
			retry = true
		default:
			retry = true
		}
	}
	if retry {
		return actionconsent.WakeSendRetry, ErrUnavailable
	}
	if accepted {
		return actionconsent.WakeSendAccepted, nil
	}
	return actionconsent.WakeSendNoInstallation, nil
}
