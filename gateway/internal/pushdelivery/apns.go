package pushdelivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	apnsProductionEndpoint   = "https://api.push.apple.com/3/device/"
	apnsDevelopmentEndpoint  = "https://api.development.push.apple.com/3/device/"
	apnsWakeBody             = `{"aps":{"content-available":1},"kind":"action-consent-wake","version":1}`
	maximumAPNsResponseBytes = 2 * 1024
)

type APNsEnvironment uint8

const (
	APNsProduction APNsEnvironment = iota + 1
	APNsDevelopment
)

type APNsProvider struct {
	client       *http.Client
	authorizer   BearerTokenProvider
	topic        string
	endpoint     string
	requireHTTP2 bool
}

var _ Provider = (*APNsProvider)(nil)

func NewAPNsProvider(client *http.Client, authorizer BearerTokenProvider,
	topic string, environment APNsEnvironment) (*APNsProvider, error) {
	if client == nil || authorizer == nil || !validAPNsTopic(topic) ||
		client.Timeout < 100*time.Millisecond || client.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	hardenedClient, err := hardenedHTTPClient(client, false, tls.VersionTLS12)
	if err != nil {
		return nil, err
	}
	endpoint := apnsProductionEndpoint
	if environment == APNsDevelopment {
		endpoint = apnsDevelopmentEndpoint
	} else if environment != APNsProduction {
		return nil, ErrInvalid
	}
	return &APNsProvider{client: hardenedClient, authorizer: authorizer,
		topic: topic, endpoint: endpoint, requireHTTP2: true}, nil
}

func (provider *APNsProvider) Send(ctx context.Context,
	deviceToken string) (DeliveryResult, error) {
	if provider == nil || ctx == nil || provider.client == nil ||
		provider.authorizer == nil || !validAPNsDeviceToken(deviceToken) {
		return DeliveryRetry, ErrInvalid
	}
	bearer, err := provider.authorizer.BearerToken(ctx)
	if err != nil || !validBearer(bearer) {
		return DeliveryRetry, fmt.Errorf("%w: APNs authorization", ErrUnavailable)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		provider.endpoint+deviceToken, bytes.NewBufferString(apnsWakeBody))
	if err != nil {
		return DeliveryRetry, ErrUnavailable
	}
	request.Header.Set("Authorization", "bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("apns-topic", provider.topic)
	request.Header.Set("apns-push-type", "background")
	request.Header.Set("apns-priority", "5")
	request.Header.Set("apns-expiration", "0")
	response, err := provider.client.Do(request)
	if err != nil {
		return DeliveryRetry, fmt.Errorf("%w: APNs transport", ErrUnavailable)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body,
		maximumAPNsResponseBytes+1))
	if readErr != nil || len(body) > maximumAPNsResponseBytes ||
		(provider.requireHTTP2 && response.ProtoMajor != 2) {
		return DeliveryRetry, fmt.Errorf("%w: APNs response", ErrUnavailable)
	}
	if response.StatusCode == http.StatusOK {
		if len(body) != 0 {
			return DeliveryRetry, fmt.Errorf("%w: APNs success body", ErrUnavailable)
		}
		return DeliveryAccepted, nil
	}
	reason := apnsReason(body)
	if response.StatusCode == http.StatusForbidden &&
		reason == "InvalidProviderToken" {
		return DeliveryRetry, fmt.Errorf("%w: %w: APNs authorization",
			ErrUnavailable, ErrCredentialRejected)
	}
	if response.StatusCode == http.StatusGone || reason == "BadDeviceToken" ||
		reason == "DeviceTokenNotForTopic" || reason == "ExpiredToken" ||
		reason == "Unregistered" {
		return DeliveryInvalidInstallation, nil
	}
	return DeliveryRetry, fmt.Errorf("%w: APNs rejected", ErrUnavailable)
}

func apnsReason(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var response struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &response); err != nil ||
		len(response.Reason) > 64 {
		return ""
	}
	return response.Reason
}

func validAPNsDeviceToken(value string) bool {
	if len(value) < 32 || len(value) > 512 || len(value)%2 != 0 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9') &&
			!(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validAPNsTopic(value string) bool {
	if len(value) < 3 || len(value) > 255 || strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'A' && character <= 'Z') &&
			!(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') && character != '.' &&
			character != '-' {
			return false
		}
	}
	return true
}
