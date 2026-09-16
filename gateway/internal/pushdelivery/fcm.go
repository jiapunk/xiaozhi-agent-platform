package pushdelivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	fcmEndpointPrefix       = "https://fcm.googleapis.com/v1/projects/"
	fcmEndpointSuffix       = "/messages:send"
	maximumFCMResponseBytes = 8 * 1024
)

type FCMProvider struct {
	client     *http.Client
	authorizer BearerTokenProvider
	projectID  string
	endpoint   string
}

var _ Provider = (*FCMProvider)(nil)

func NewFCMProvider(client *http.Client, authorizer BearerTokenProvider,
	projectID string) (*FCMProvider, error) {
	if client == nil || authorizer == nil || !validFCMProjectID(projectID) ||
		client.Timeout < 100*time.Millisecond || client.Timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	hardenedClient, err := hardenedHTTPClient(client, false, tls.VersionTLS12)
	if err != nil {
		return nil, err
	}
	return &FCMProvider{client: hardenedClient, authorizer: authorizer,
		projectID: projectID,
		endpoint:  fcmEndpointPrefix + projectID + fcmEndpointSuffix}, nil
}

func (provider *FCMProvider) Send(ctx context.Context,
	registrationToken string) (DeliveryResult, error) {
	if provider == nil || ctx == nil || provider.client == nil ||
		provider.authorizer == nil || !validFCMRegistrationToken(registrationToken) {
		return DeliveryRetry, ErrInvalid
	}
	bearer, err := provider.authorizer.BearerToken(ctx)
	if errors.Is(err, ErrCredentialRejected) {
		return DeliveryRetry, fmt.Errorf("%w: FCM authorization", err)
	}
	if err != nil || !validBearer(bearer) {
		return DeliveryRetry, fmt.Errorf("%w: FCM authorization", ErrUnavailable)
	}
	body, err := canonicalFCMWakeBody(registrationToken)
	if err != nil {
		return DeliveryRetry, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		provider.endpoint, bytes.NewReader(body))
	if err != nil {
		return DeliveryRetry, ErrUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := provider.client.Do(request)
	if err != nil {
		return DeliveryRetry, fmt.Errorf("%w: FCM transport", ErrUnavailable)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body,
		maximumFCMResponseBytes+1))
	if readErr != nil || len(responseBody) > maximumFCMResponseBytes {
		return DeliveryRetry, fmt.Errorf("%w: FCM response", ErrUnavailable)
	}
	if response.StatusCode == http.StatusOK {
		if !validFCMSuccess(responseBody) {
			return DeliveryRetry, fmt.Errorf("%w: FCM success response", ErrUnavailable)
		}
		return DeliveryAccepted, nil
	}
	if fcmInvalidInstallation(responseBody) {
		return DeliveryInvalidInstallation, nil
	}
	return DeliveryRetry, fmt.Errorf("%w: FCM rejected", ErrUnavailable)
}

func canonicalFCMWakeBody(registrationToken string) ([]byte, error) {
	message := struct {
		Message struct {
			Token   string            `json:"token"`
			Data    map[string]string `json:"data"`
			Android struct {
				Priority string `json:"priority"`
				TTL      string `json:"ttl"`
			} `json:"android"`
		} `json:"message"`
	}{}
	message.Message.Token = registrationToken
	message.Message.Data = map[string]string{
		"kind": "action-consent-wake", "version": "1",
	}
	message.Message.Android.Priority = "normal"
	message.Message.Android.TTL = "0s"
	return json.Marshal(message)
}

func validFCMSuccess(body []byte) bool {
	var response struct {
		Name string `json:"name"`
	}
	return json.Unmarshal(body, &response) == nil &&
		strings.HasPrefix(response.Name, "projects/") &&
		len(response.Name) <= 512
}

func fcmInvalidInstallation(body []byte) bool {
	var response struct {
		Error struct {
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		return false
	}
	for _, detail := range response.Error.Details {
		if detail.Type == "type.googleapis.com/google.firebase.fcm.v1.FcmError" &&
			(detail.ErrorCode == "UNREGISTERED" ||
				detail.ErrorCode == "INVALID_ARGUMENT") {
			return true
		}
	}
	return false
}

func validFCMRegistrationToken(value string) bool {
	if len(value) < 20 || len(value) > 4096 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'A' && character <= 'Z') &&
			!(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') &&
			character != ':' && character != '_' && character != '-' &&
			character != '.' && character != '~' {
			return false
		}
	}
	return true
}

func validFCMProjectID(value string) bool {
	if len(value) < 6 || len(value) > 30 || value[0] < 'a' || value[0] > 'z' ||
		value[len(value)-1] == '-' {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') && character != '-' {
			return false
		}
	}
	return true
}
