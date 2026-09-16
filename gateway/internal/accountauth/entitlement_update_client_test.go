package accountauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

type entitlementUpdateClientTestSigner struct {
	mu         sync.Mutex
	keyID      string
	privateKey ed25519.PrivateKey
	error      error
	calls      int
	payloads   [][]byte
}

func (signer *entitlementUpdateClientTestSigner) KeyID() string {
	if signer == nil {
		return ""
	}
	signer.mu.Lock()
	defer signer.mu.Unlock()
	return signer.keyID
}

func (signer *entitlementUpdateClientTestSigner) Sign(_ context.Context,
	payload []byte) ([]byte, error) {
	signer.mu.Lock()
	defer signer.mu.Unlock()
	signer.calls++
	signer.payloads = append(signer.payloads, append([]byte(nil), payload...))
	if signer.error != nil {
		return nil, signer.error
	}
	return ed25519.Sign(signer.privateKey, payload), nil
}

func entitlementUpdateClientFixture(t *testing.T) (
	*entitlementUpdateClientTestSigner, time.Time, ServiceEntitlementUpdate) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 85
	signer := &entitlementUpdateClientTestSigner{
		keyID:      "billing-adapter-1",
		privateKey: ed25519.NewKeyFromSeed(seed),
	}
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	update := entitlementUpdate(
		Principal{TenantID: "tenant-1", Subject: "owner-1"},
		"billing-event-1", 0, 1, EntitlementActive, true, true,
		now.Add(30*24*time.Hour))
	return signer, now, update
}

func setEntitlementUpdateClientResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set(EntitlementUpdateContractHeader,
		ServiceEntitlementUpdateContract)
}

func TestHTTPServiceEntitlementUpdaterSignsCanonicalSingleDelivery(t *testing.T) {
	signer, now, update := entitlementUpdateClientFixture(t)
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		requestCount++
		if request.Method != http.MethodPost ||
			request.URL.Path != ServiceEntitlementUpdatePath ||
			request.URL.RawQuery != "" ||
			request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Cache-Control") != "no-store" ||
			request.Header.Get(EntitlementUpdateContractHeader) !=
				ServiceEntitlementUpdateContract ||
			request.Header.Get(EntitlementUpdateKeyIDHeader) != signer.keyID {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || request.ContentLength != int64(len(body)) {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var input serviceEntitlementUpdateRequest
		if err := json.Unmarshal(body, &input); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		canonical, _ := json.Marshal(input)
		signature, err := base64.RawURLEncoding.Strict().DecodeString(
			request.Header.Get(EntitlementUpdateSignatureHeader))
		if err != nil || !bytes.Equal(canonical, body) ||
			!ed25519.Verify(signer.privateKey.Public().(ed25519.PublicKey),
				serviceEntitlementUpdateSigningMessage(body), signature) ||
			input.AuthorizedAt != now.Unix() ||
			input.AuthorizationExpiresAt != now.Add(5*time.Minute).Unix() {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		response, _ := json.Marshal(serviceEntitlementUpdateResponse{
			Version: 1, Status: "applied",
			SourceEventID: input.SourceEventID, Revision: input.Revision,
		})
		setEntitlementUpdateClientResponseHeaders(writer.Header())
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Content-Length", stringInt(len(response)))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(response)
	}))
	defer server.Close()
	server.Client().Timeout = time.Second
	updater, err := NewHTTPServiceEntitlementUpdater(
		server.URL+ServiceEntitlementUpdatePath,
		&EntitlementUpdateMTLSClient{client: server.Client()}, signer,
		5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	updater.now = func() time.Time { return now }
	result, err := updater.Apply(context.Background(), update)
	if err != nil || result.Disposition != EntitlementUpdateApplied ||
		result.SourceEventID != update.SourceEventID ||
		result.Revision != update.Revision || requestCount != 1 ||
		signer.calls != 1 || len(signer.payloads) != 1 ||
		!bytes.HasPrefix(signer.payloads[0],
			[]byte(entitlementUpdateSignatureDomain)) {
		t.Fatalf("result=%#v requests=%d signer=%#v err=%v",
			result, requestCount, signer, err)
	}
}

func TestHTTPServiceEntitlementUpdaterClassifiesExactFailuresWithoutRetry(
	t *testing.T) {
	signer, now, update := entitlementUpdateClientFixture(t)
	for name, testCase := range map[string]struct {
		status     int
		retryAfter string
		expected   error
	}{
		"invalid event": {http.StatusBadRequest, "", ErrInvalid},
		"signer unauthorized": {http.StatusUnauthorized, "",
			ErrEntitlementUpdateUnauthorized},
		"account missing":   {http.StatusNotFound, "", ErrNotFound},
		"revision conflict": {http.StatusConflict, "", ErrConflict},
		"service unavailable": {http.StatusServiceUnavailable, "1",
			ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					calls++
					setEntitlementUpdateClientResponseHeaders(writer.Header())
					if testCase.retryAfter != "" {
						writer.Header().Set("Retry-After", testCase.retryAfter)
					}
					writer.WriteHeader(testCase.status)
				}))
			defer server.Close()
			server.Client().Timeout = time.Second
			updater, err := NewHTTPServiceEntitlementUpdater(
				server.URL+ServiceEntitlementUpdatePath,
				&EntitlementUpdateMTLSClient{client: server.Client()}, signer,
				5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			updater.now = func() time.Time { return now }
			result, err := updater.Apply(context.Background(), update)
			if !errors.Is(err, testCase.expected) ||
				result != (EntitlementUpdateResult{}) || calls != 1 {
				t.Fatalf("result=%#v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestHTTPServiceEntitlementUpdaterRejectsMalformedSuccessAndRedirect(
	t *testing.T) {
	signer, now, update := entitlementUpdateClientFixture(t)
	for name, handler := range map[string]http.HandlerFunc{
		"mismatched event": func(writer http.ResponseWriter, _ *http.Request) {
			body := []byte(`{"version":1,"status":"applied","source_event_id":"other-event","revision":1}`)
			setEntitlementUpdateClientResponseHeaders(writer.Header())
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Content-Length", stringInt(len(body)))
			_, _ = writer.Write(body)
		},
		"noncanonical response": func(writer http.ResponseWriter,
			_ *http.Request) {
			body := []byte(" " +
				`{"version":1,"status":"applied","source_event_id":"billing-event-1","revision":1}`)
			setEntitlementUpdateClientResponseHeaders(writer.Header())
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Content-Length", stringInt(len(body)))
			_, _ = writer.Write(body)
		},
		"redirect": func(writer http.ResponseWriter, request *http.Request) {
			http.Redirect(writer, request, "/elsewhere",
				http.StatusTemporaryRedirect)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			server.Client().Timeout = time.Second
			updater, err := NewHTTPServiceEntitlementUpdater(
				server.URL+ServiceEntitlementUpdatePath,
				&EntitlementUpdateMTLSClient{client: server.Client()}, signer,
				5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			updater.now = func() time.Time { return now }
			if _, err := updater.Apply(context.Background(), update); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("malformed response err=%v", err)
			}
		})
	}
}

func TestHTTPServiceEntitlementUpdaterRejectsSignerFailureAndMutation(
	t *testing.T) {
	signer, now, update := entitlementUpdateClientFixture(t)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter,
		*http.Request) {
		requests++
	}))
	defer server.Close()
	server.Client().Timeout = time.Second
	updater, err := NewHTTPServiceEntitlementUpdater(
		server.URL+ServiceEntitlementUpdatePath,
		&EntitlementUpdateMTLSClient{client: server.Client()}, signer,
		5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	updater.now = func() time.Time { return now }
	signer.error = errors.New("HSM unavailable")
	if _, err := updater.Apply(context.Background(), update); !errors.Is(err, ErrUnavailable) || requests != 0 {
		t.Fatalf("signer failure requests=%d err=%v", requests, err)
	}
	signer.error = nil
	signer.keyID = "billing-adapter-2"
	if _, err := updater.Apply(context.Background(), update); !errors.Is(err, ErrInvalid) || requests != 0 {
		t.Fatalf("signer mutation requests=%d err=%v", requests, err)
	}
}

func TestHTTPServiceEntitlementUpdaterRejectsUnsafeConfiguration(t *testing.T) {
	signer, _, _ := entitlementUpdateClientFixture(t)
	client := &EntitlementUpdateMTLSClient{client: &http.Client{
		Timeout: time.Second}}
	for _, endpoint := range []string{
		"http://account.example" + ServiceEntitlementUpdatePath,
		"https://account.example/v1/other",
		"https://user@account.example" + ServiceEntitlementUpdatePath,
		"https://account.example" + ServiceEntitlementUpdatePath + "?debug=1",
	} {
		if _, err := NewHTTPServiceEntitlementUpdater(endpoint, client, signer,
			5*time.Minute); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if _, err := NewHTTPServiceEntitlementUpdater(
		"https://account.example"+ServiceEntitlementUpdatePath,
		&EntitlementUpdateMTLSClient{client: &http.Client{}}, signer,
		5*time.Minute); err == nil {
		t.Fatal("unbounded HTTP client accepted")
	}
	if _, err := NewServiceEntitlementUpdateMTLSClient(nil, nil, nil,
		time.Second); err == nil {
		t.Fatal("empty mTLS identity accepted")
	}
}

func stringInt(value int) string {
	return strconv.Itoa(value)
}
