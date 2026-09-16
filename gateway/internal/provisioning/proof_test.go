package provisioning

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
)

type proofTestCoordinator struct {
	reserveError error
	scope        uint8
	subject      string
	nonce        string
}

func (*proofTestCoordinator) VerifySchema(context.Context) error { return nil }
func (coordinator *proofTestCoordinator) ReserveProof(_ context.Context,
	scope uint8, subject, nonce string, _, _ time.Duration) error {
	coordinator.scope, coordinator.subject, coordinator.nonce = scope, subject, nonce
	return coordinator.reserveError
}
func (*proofTestCoordinator) ConsumeVoiceToken(context.Context, string, string,
	time.Time) error {
	return nil
}
func (*proofTestCoordinator) AcquireVoice(context.Context, string, int,
	time.Duration) (runtimecoordination.Lease, error) {
	return runtimecoordination.Lease{}, nil
}
func (*proofTestCoordinator) AcquireAgent(context.Context, string, int, int,
	time.Duration) (runtimecoordination.Lease, error) {
	return runtimecoordination.Lease{}, nil
}
func (*proofTestCoordinator) Renew(context.Context, runtimecoordination.Lease,
	time.Duration) (runtimecoordination.Lease, error) {
	return runtimecoordination.Lease{}, nil
}
func (*proofTestCoordinator) Release(context.Context,
	runtimecoordination.Lease) error {
	return nil
}

var testDeviceSecret = []byte("device-secret-0123456789abcdef012345")

func testRegistryJSON(deviceID string, disabled bool) string {
	return `{"version":1,"devices":[{"device_id":"` + deviceID +
		`","secret_b64":"` + base64.RawURLEncoding.EncodeToString(testDeviceSecret) +
		`","disabled":` + map[bool]string{true: "true", false: "false"}[disabled] + `}]}`
}

func testProofVerifier(t *testing.T, disabled bool) (*ProofVerifier, time.Time) {
	t.Helper()
	registry, err := ParseRegistry(strings.NewReader(testRegistryJSON("device-1", disabled)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewProofVerifier(registry, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	return verifier, now
}

func signedProofRequest(t *testing.T, now time.Time, nonce []byte, secret []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := now.Unix()
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(HeaderDeviceID, "device-1")
	request.Header.Set(HeaderClientID, "client-1")
	request.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	request.Header.Set(HeaderNonce, nonceText)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(CanonicalProof(
		"device-1", "client-1", strconv.FormatInt(timestamp, 10), nonceText)))
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestProofAuthorizationReplayAndRateLimit(t *testing.T) {
	verifier, now := testProofVerifier(t, false)
	first := signedProofRequest(t, now, []byte("0123456789abcdef"), testDeviceSecret)
	deviceID, err := verifier.Authorize(first)
	if err != nil || deviceID != "device-1" {
		t.Fatalf("authorize: device=%q err=%v", deviceID, err)
	}
	if _, err := verifier.Authorize(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v, want replay", err)
	}
	second := signedProofRequest(t, now, []byte("abcdef0123456789"), testDeviceSecret)
	if _, err := verifier.Authorize(second); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("got %v, want rate limit", err)
	}
	verifier.now = func() time.Time { return now.Add(6 * time.Second) }
	third := signedProofRequest(t, now.Add(6*time.Second),
		[]byte("fedcba9876543210"), testDeviceSecret)
	if _, err := verifier.Authorize(third); err != nil {
		t.Fatal(err)
	}
}

func TestProofAuthorizationUsesSharedCoordinatorAndMapsFailures(t *testing.T) {
	verifier, now := testProofVerifier(t, false)
	coordinator := &proofTestCoordinator{}
	if err := verifier.SetCoordinator(coordinator); err != nil {
		t.Fatal(err)
	}
	request := signedProofRequest(t, now, []byte("0123456789abcdef"),
		testDeviceSecret)
	if deviceID, err := verifier.Authorize(request); err != nil ||
		deviceID != "device-1" || coordinator.scope != uint8(SessionProofScope) ||
		coordinator.subject != "device-1" || coordinator.nonce == "" {
		t.Fatalf("shared authorization: device=%q coordinator=%#v err=%v",
			deviceID, coordinator, err)
	}
	for shared, expected := range map[error]error{
		runtimecoordination.ErrReplay:      ErrReplay,
		runtimecoordination.ErrRateLimited: ErrRateLimited,
		runtimecoordination.ErrUnavailable: ErrUnavailable,
		runtimecoordination.ErrInvalid:     ErrUnavailable,
	} {
		coordinator.reserveError = shared
		if _, err := verifier.Authorize(request); !errors.Is(err, expected) {
			t.Fatalf("shared error %v mapped to %v, want %v", shared, err, expected)
		}
	}
	if err := (*ProofVerifier)(nil).SetCoordinator(coordinator); err == nil {
		t.Fatal("nil proof verifier accepted coordinator")
	}
}

func TestProofRejectsBodyQueryAndFutureTimestamp(t *testing.T) {
	verifier, now := testProofVerifier(t, false)
	withQuery := signedProofRequest(t, now, []byte("0123456789abcdef"), testDeviceSecret)
	withQuery.URL.RawQuery = "ignored=true"
	if _, err := verifier.Authorize(withQuery); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("query: %v", err)
	}

	withBody := signedProofRequest(t, now, []byte("abcdef0123456789"), testDeviceSecret)
	withBody.ContentLength = -1
	if _, err := verifier.Authorize(withBody); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("unknown body length: %v", err)
	}

	future := signedProofRequest(t, now.Add(2*time.Minute),
		[]byte("fedcba9876543210"), testDeviceSecret)
	if _, err := verifier.Authorize(future); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("future proof: %v", err)
	}
}

func TestProofRejectsDuplicateSecurityHeader(t *testing.T) {
	verifier, now := testProofVerifier(t, false)
	request := signedProofRequest(t, now, []byte("0123456789abcdef"), testDeviceSecret)
	request.Header.Add(HeaderDeviceID, "device-1")
	if _, err := verifier.Authorize(request); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("duplicate header: %v", err)
	}
}

func TestProofRejectsBadSignatureSkewDisabledAndMalformed(t *testing.T) {
	verifier, now := testProofVerifier(t, false)
	badSignature := signedProofRequest(t, now, []byte("0123456789abcdef"),
		[]byte("other-secret-0123456789abcdef0123456"))
	if _, err := verifier.Authorize(badSignature); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad signature: %v", err)
	}
	stale := signedProofRequest(t, now.Add(-2*time.Minute),
		[]byte("abcdef0123456789"), testDeviceSecret)
	if _, err := verifier.Authorize(stale); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale proof: %v", err)
	}
	disabled, _ := testProofVerifier(t, true)
	if _, err := disabled.Authorize(signedProofRequest(
		t, now, []byte("fedcba9876543210"), testDeviceSecret)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled device: %v", err)
	}
	malformed := signedProofRequest(t, now, []byte("1111111111111111"), testDeviceSecret)
	malformed.Header.Set(HeaderNonce, "bad")
	if _, err := verifier.Authorize(malformed); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("malformed proof: %v", err)
	}
}

func TestRegistryRejectsUnknownDuplicateAndWeakEntries(t *testing.T) {
	cases := []string{
		`{"version":1,"unknown":true,"devices":[]}`,
		`{"version":1,"devices":[{"device_id":"d","secret_b64":"` +
			base64.RawURLEncoding.EncodeToString(testDeviceSecret) + `"},` +
			`{"device_id":"d","secret_b64":"` +
			base64.RawURLEncoding.EncodeToString(testDeviceSecret) + `"}]}`,
		`{"version":1,"devices":[{"device_id":"d","secret_b64":"d2Vhaw"}]}`,
	}
	for _, input := range cases {
		if _, err := ParseRegistry(strings.NewReader(input)); err == nil {
			t.Fatalf("expected rejection for %s", input)
		}
	}
}

func TestProofScopeIsolation(t *testing.T) {
	registry, err := ParseRegistry(strings.NewReader(
		testRegistryJSON("device-1", false)))
	if err != nil {
		t.Fatal(err)
	}
	agentVerifier, err := NewScopedProofVerifier(registry,
		AgentTokenProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	agentVerifier.now = func() time.Time { return now }
	nonceText := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef"))
	timestampText := strconv.FormatInt(now.Unix(), 10)
	request, err := http.NewRequest(http.MethodPost,
		"https://control.example/v1/agent-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(HeaderDeviceID, "device-1")
	request.Header.Set(HeaderClientID, "client-1")
	request.Header.Set(HeaderTimestamp, timestampText)
	request.Header.Set(HeaderNonce, nonceText)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(CanonicalScopedProof(AgentTokenProofScope,
		"device-1", "client-1", timestampText, nonceText)))
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	if deviceID, err := agentVerifier.Authorize(request); err != nil || deviceID != "device-1" {
		t.Fatalf("agent proof: device=%q err=%v", deviceID, err)
	}

	wrongPath := signedProofRequest(t, now,
		[]byte("abcdef0123456789"), testDeviceSecret)
	if _, err := agentVerifier.Authorize(wrongPath); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("session proof reached Agent scope: %v", err)
	}
	if CanonicalScopedProof(0, "d", "c", "1", "n") != "" {
		t.Fatal("unknown proof scope must not produce bytes")
	}
}

func otaProofRequest(t *testing.T, now time.Time, nonce []byte,
	board, channel, sequence, version string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost,
		"https://control.example/v1/ota/offer", nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(HeaderDeviceID, "device-1")
	request.Header.Set(HeaderClientID, "client-1")
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonceText)
	request.Header.Set(HeaderOTABoard, board)
	request.Header.Set(HeaderOTAChannel, channel)
	request.Header.Set(HeaderOTASequence, sequence)
	request.Header.Set(HeaderOTAVersion, version)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(CanonicalOTAProof(
		"device-1", "client-1", timestamp, nonceText, board, channel,
		sequence, version)))
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestOTAProofBindsRegisteredProfileAndCompleteDeviceState(t *testing.T) {
	registryJSON := `{"version":1,"devices":[{"device_id":"device-1",` +
		`"secret_b64":"` + base64.RawURLEncoding.EncodeToString(testDeviceSecret) +
		`","board":"esp32s3-box3","ota_channel":"development"}]}`
	registry, err := ParseRegistry(strings.NewReader(registryJSON))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewScopedProofVerifier(registry, OTAOfferProofScope,
		time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	request := otaProofRequest(t, now, []byte("0123456789abcdef"),
		"esp32s3-box3", "development", "14", "0.14.0-dev")
	if deviceID, err := verifier.Authorize(request); err != nil ||
		deviceID != "device-1" {
		t.Fatalf("OTA proof: device=%q err=%v", deviceID, err)
	}
	if _, err := verifier.Authorize(request); !errors.Is(err, ErrReplay) {
		t.Fatalf("OTA proof replay: %v", err)
	}
	wrongBoard := otaProofRequest(t, now, []byte("abcdef0123456789"),
		"esp32s3-n32r16", "development", "14", "0.14.0-dev")
	if _, err := verifier.Authorize(wrongBoard); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unregistered board profile: %v", err)
	}
	nonCanonicalSequence := otaProofRequest(t, now,
		[]byte("fedcba9876543210"), "esp32s3-box3", "development", "014",
		"0.14.0-dev")
	if _, err := verifier.Authorize(nonCanonicalSequence); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("non-canonical sequence: %v", err)
	}
	sessionVerifier, err := NewScopedProofVerifier(registry,
		SessionProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessionVerifier.Authorize(otaProofRequest(t, now,
		[]byte("1111111111111111"), "esp32s3-box3", "development", "14",
		"0.14.0-dev")); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("OTA proof reached session scope: %v", err)
	}
}

func deviceClaimProofRequest(t *testing.T, now time.Time, nonce []byte,
	claim string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost,
		"https://control.example/v1/device-claim/device", nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(HeaderDeviceID, "device-1")
	request.Header.Set(HeaderClientID, "client-1")
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonceText)
	request.Header.Set(HeaderDeviceClaim, claim)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(CanonicalDeviceClaimProof(
		"device-1", "client-1", timestamp, nonceText, claim)))
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestDeviceClaimProofBindsClaimAndIsScopeIsolated(t *testing.T) {
	registry, err := ParseRegistry(strings.NewReader(
		testRegistryJSON("device-1", false)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewScopedProofVerifier(registry,
		DeviceClaimProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	claim := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	request := deviceClaimProofRequest(t, now,
		[]byte("0123456789abcdef"), claim)
	if deviceID, err := verifier.Authorize(request); err != nil ||
		deviceID != "device-1" {
		t.Fatalf("device claim proof: %q %v", deviceID, err)
	}

	tampered := deviceClaimProofRequest(t, now,
		[]byte("abcdef0123456789"), claim)
	tampered.Header.Set(HeaderDeviceClaim,
		base64.RawURLEncoding.EncodeToString(
			[]byte("fedcba9876543210fedcba9876543210")))
	if _, err := verifier.Authorize(tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered claim: %v", err)
	}
	missing := deviceClaimProofRequest(t, now,
		[]byte("fedcba9876543210"), claim)
	missing.Header.Del(HeaderDeviceClaim)
	if _, err := verifier.Authorize(missing); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("missing claim: %v", err)
	}
	sessionVerifier, err := NewScopedProofVerifier(registry,
		SessionProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessionVerifier.Authorize(deviceClaimProofRequest(t, now,
		[]byte("1111111111111111"), claim)); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("claim proof reached session scope: %v", err)
	}
	if CanonicalDeviceClaimProof("d", "c", "1", "n", "bad") != "" {
		t.Fatal("invalid claim produced canonical bytes")
	}
}

func actionConsentProofVerifier(t *testing.T,
	scope ProofScope) (*ProofVerifier, time.Time) {
	t.Helper()
	registry, err := ParseRegistry(strings.NewReader(
		testRegistryJSON("device-1", false)))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewScopedProofVerifier(registry, scope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	return verifier, now
}

func actionConsentProofRequest(t *testing.T, scope ProofScope, now time.Time,
	nonce, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost,
		"https://control.example"+proofPath(scope), strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	bodyDigest := sha256.Sum256(body)
	bodyDigestText := fmt.Sprintf("%x", bodyDigest[:])
	request.Header.Set(HeaderDeviceID, "device-1")
	request.Header.Set(HeaderClientID, "client-1")
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonceText)
	request.Header.Set(HeaderActionConsentBodySHA256, bodyDigestText)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(CanonicalActionConsentProof(scope, "device-1",
		"client-1", timestamp, nonceText, bodyDigestText)))
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestActionConsentProofBindsBodyAndSeparatesScopes(t *testing.T) {
	body := []byte(`{"version":1,"challenge_id":"MDEyMzQ1Njc4OWFiY2RlZg"}`)
	for _, scope := range []ProofScope{
		ActionConsentChallengeProofScope,
		ActionConsentResultProofScope,
	} {
		verifier, now := actionConsentProofVerifier(t, scope)
		request := actionConsentProofRequest(t, scope, now,
			[]byte("0123456789abcdef"), body)
		deviceID, err := verifier.AuthorizeBody(request, body)
		if err != nil || deviceID != "device-1" {
			t.Fatalf("scope %d: device=%q err=%v", scope, deviceID, err)
		}
		if _, err := verifier.AuthorizeBody(request, body); !errors.Is(err, ErrReplay) {
			t.Fatalf("scope %d replay: %v", scope, err)
		}

		wrongPath := actionConsentProofRequest(t, scope, now,
			[]byte("abcdef0123456789"), body)
		if scope == ActionConsentChallengeProofScope {
			wrongPath.URL.Path = proofPath(ActionConsentResultProofScope)
		} else {
			wrongPath.URL.Path = proofPath(ActionConsentChallengeProofScope)
		}
		if _, err := verifier.AuthorizeBody(wrongPath, body); !errors.Is(err, ErrMalformedProof) {
			t.Fatalf("scope %d wrong path: %v", scope, err)
		}
	}

	challengeVerifier, now := actionConsentProofVerifier(t,
		ActionConsentChallengeProofScope)
	resultRequest := actionConsentProofRequest(t, ActionConsentResultProofScope,
		now, []byte("fedcba9876543210"), body)
	resultRequest.URL.Path = proofPath(ActionConsentChallengeProofScope)
	if _, err := challengeVerifier.AuthorizeBody(resultRequest, body); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("result proof reached challenge scope: %v", err)
	}
}

func TestActionConsentProofRejectsBodyAndTransportMutation(t *testing.T) {
	verifier, now := actionConsentProofVerifier(t,
		ActionConsentChallengeProofScope)
	body := []byte(`{"version":1,"challenge_id":"MDEyMzQ1Njc4OWFiY2RlZg"}`)
	mutatedBody := []byte(`{"version":1,"challenge_id":"ZmVkY2JhOTg3NjU0MzIxMA"}`)

	staleDigest := actionConsentProofRequest(t,
		ActionConsentChallengeProofScope, now,
		[]byte("0123456789abcdef"), body)
	staleDigest.ContentLength = int64(len(mutatedBody))
	if _, err := verifier.AuthorizeBody(staleDigest, mutatedBody); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("body changed under digest: %v", err)
	}

	staleSignature := actionConsentProofRequest(t,
		ActionConsentChallengeProofScope, now,
		[]byte("abcdef0123456789"), body)
	mutatedDigest := sha256.Sum256(mutatedBody)
	staleSignature.Header.Set(HeaderActionConsentBodySHA256,
		fmt.Sprintf("%x", mutatedDigest[:]))
	staleSignature.ContentLength = int64(len(mutatedBody))
	if _, err := verifier.AuthorizeBody(staleSignature, mutatedBody); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("digest changed under signature: %v", err)
	}

	duplicateDigest := actionConsentProofRequest(t,
		ActionConsentChallengeProofScope, now,
		[]byte("fedcba9876543210"), body)
	duplicateDigest.Header.Add(HeaderActionConsentBodySHA256,
		duplicateDigest.Header.Get(HeaderActionConsentBodySHA256))
	if _, err := verifier.AuthorizeBody(duplicateDigest, body); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("duplicate digest header: %v", err)
	}

	unknownLength := actionConsentProofRequest(t,
		ActionConsentChallengeProofScope, now,
		[]byte("1111111111111111"), body)
	unknownLength.ContentLength = -1
	if _, err := verifier.AuthorizeBody(unknownLength, body); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("unknown body length: %v", err)
	}

	chunked := actionConsentProofRequest(t,
		ActionConsentChallengeProofScope, now,
		[]byte("2222222222222222"), body)
	chunked.TransferEncoding = []string{"chunked"}
	if _, err := verifier.AuthorizeBody(chunked, body); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("chunked body: %v", err)
	}

	withoutBodyAPI := actionConsentProofRequest(t,
		ActionConsentChallengeProofScope, now,
		[]byte("3333333333333333"), body)
	if _, err := verifier.Authorize(withoutBodyAPI); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("body proof accepted by bodyless API: %v", err)
	}

	sessionVerifier, _ := testProofVerifier(t, false)
	sessionRequest := signedProofRequest(t, now,
		[]byte("4444444444444444"), testDeviceSecret)
	if _, err := sessionVerifier.AuthorizeBody(sessionRequest, body); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("session proof accepted a protected body: %v", err)
	}

	validDigest := strings.Repeat("a", 64)
	if CanonicalActionConsentProof(SessionProofScope, "d", "c", "1", "n",
		validDigest) != "" || CanonicalActionConsentProof(
		ActionConsentChallengeProofScope, "d", "c", "1", "n",
		strings.ToUpper(validDigest)) != "" {
		t.Fatal("invalid action consent proof produced canonical bytes")
	}
}
