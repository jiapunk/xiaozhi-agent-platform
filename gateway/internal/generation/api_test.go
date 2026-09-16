package generation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

var (
	testPublisherKey = []byte("generation-publisher-0123456789abcdef012")
	testControlKey   = []byte("generation-control-a-0123456789abcdef01")
	testOriginKey    = []byte("generation-origin-a-0123456789abcdef012")
)

type coordinatorFixture struct {
	store     *Store
	server    *httptest.Server
	publisher *Client
	control   *Client
	origin    *Client
	now       *time.Time
}

func newCoordinatorFixture(t *testing.T) coordinatorFixture {
	t.Helper()
	now := testNow
	registryFile := filepath.Join(t.TempDir(), "replicas.json")
	document := replicaRegistryDocument{Version: 1, Replicas: []ReplicaIdentity{
		{ReplicaID: "controlplane-a", Role: "controlplane",
			HMACKeyB64: base64.RawURLEncoding.EncodeToString(testControlKey)},
		{ReplicaID: "firmwareorigin-a", Role: "firmwareorigin",
			HMACKeyB64: base64.RawURLEncoding.EncodeToString(testOriginKey)},
	}}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryFile, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadReplicaRegistry(registryFile)
	if err != nil {
		t.Fatal(err)
	}
	store, err := InitializeStore(filepath.Join(t.TempDir(), "state"), testStateKey,
		testGenesis, registry.References(), now)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewServer(ServerConfig{
		Store: store, Publisher: Principal{ID: "release-publisher", Role: "publisher",
			Key: testPublisherKey}, Replicas: registry,
		PrepareTimeout: time.Minute, CommitTimeout: time.Minute,
		MaxClockSkew: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(coordinator.Handler())
	makeClient := func(principal Principal) *Client {
		client, clientErr := NewClient(server.URL, principal, nil, true)
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		client.now = func() time.Time { return now }
		return client
	}
	fixture := coordinatorFixture{
		store: store, server: server, now: &now,
		publisher: makeClient(Principal{ID: "release-publisher", Role: "publisher",
			Key: testPublisherKey}),
		control: makeClient(Principal{ID: "controlplane-a", Role: "controlplane",
			Key: testControlKey}),
		origin: makeClient(Principal{ID: "firmwareorigin-a", Role: "firmwareorigin",
			Key: testOriginKey}),
	}
	// Replace closures with a shared mutable clock.
	coordinator.config.Now = func() time.Time { return *fixture.now }
	fixture.publisher.now = func() time.Time { return *fixture.now }
	fixture.control.now = func() time.Time { return *fixture.now }
	fixture.origin.now = func() time.Time { return *fixture.now }
	t.Cleanup(func() { server.Close(); _ = store.Close() })
	return fixture
}

func TestAuthenticatedCoordinatorAPIAndRoleBoundCAS(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	ctx := context.Background()
	view, err := fixture.publisher.GetState(ctx)
	if err != nil || view.Phase != PhaseStable || view.Active != testGenesis {
		t.Fatalf("initial state=%#v err=%v", view, err)
	}
	view, err = fixture.publisher.Publish(ctx, PublishRequest{
		ExpectedRevision: view.Revision, ExpectedActive: view.Active, Pending: testNext,
	})
	if err != nil || view.Phase != PhasePreparing {
		t.Fatalf("publish state=%#v err=%v", view, err)
	}
	if _, err := fixture.publisher.Publish(ctx, PublishRequest{
		ExpectedRevision: 1, ExpectedActive: testGenesis, Pending: testNext,
	}); err != ErrConflict {
		t.Fatalf("stale publish CAS accepted: %v", err)
	}
	if _, err := fixture.publisher.Acknowledge(ctx, AckRequest{}); err == nil {
		t.Fatal("publisher client acknowledged replica state")
	}
	view, err = fixture.control.Acknowledge(ctx, AckRequest{
		ExpectedRevision: view.Revision, Generation: testNext, Stage: AckPrepared,
	})
	if err != nil || view.Phase != PhasePreparing {
		t.Fatal(err)
	}
	view, err = fixture.origin.Acknowledge(ctx, AckRequest{
		ExpectedRevision: view.Revision, Generation: testNext, Stage: AckPrepared,
	})
	if err != nil || view.Phase != PhaseDraining || view.Active != testGenesis {
		t.Fatalf("drain state=%#v err=%v", view, err)
	}
	*fixture.now = time.Unix(view.DrainUntil, 0)
	view, err = fixture.control.GetState(ctx)
	if err != nil || view.Phase != PhaseCommitting || view.Active != testNext {
		t.Fatalf("commit state=%#v err=%v", view, err)
	}
	view, err = fixture.control.Acknowledge(ctx, AckRequest{
		ExpectedRevision: view.Revision, Generation: testNext, Stage: AckActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err = fixture.origin.Acknowledge(ctx, AckRequest{
		ExpectedRevision: view.Revision, Generation: testNext, Stage: AckActive,
	})
	if err != nil || view.Phase != PhaseStable || view.Active != testNext {
		t.Fatalf("converged state=%#v err=%v", view, err)
	}
}

func TestCoordinatorRejectsReplayWrongSignatureAndNoncanonicalBody(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	request := signedRawRequest(t, fixture.server.URL, http.MethodGet,
		pathState, nil, "controlplane-a", testControlKey, *fixture.now,
		base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")))
	first, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", first.StatusCode)
	}
	replay := signedRawRequest(t, fixture.server.URL, http.MethodGet,
		pathState, nil, "controlplane-a", testControlKey, *fixture.now,
		base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")))
	second, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status=%d", second.StatusCode)
	}
	wrong := signedRawRequest(t, fixture.server.URL, http.MethodGet,
		pathState, nil, "controlplane-a", testPublisherKey, *fixture.now,
		base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210")))
	wrongResponse, err := http.DefaultClient.Do(wrong)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongResponse.Body.Close()
	if wrongResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-key status=%d", wrongResponse.StatusCode)
	}
	payload := []byte(`{ "expected_revision":1,"expected_active":{"generation_id":"staging","generation_sequence":0,"receipt_sha256":"` +
		testGenesis.ReceiptSHA256 + `"},"pending":{"generation_id":"release-15-g0001","generation_sequence":1,"receipt_sha256":"` + testNext.ReceiptSHA256 + `"}}`)
	noncanonical := signedRawRequest(t, fixture.server.URL, http.MethodPost,
		pathPublish, payload, "release-publisher", testPublisherKey, *fixture.now,
		base64.RawURLEncoding.EncodeToString([]byte("noncanonical-001")))
	noncanonical.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(noncanonical)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("noncanonical body status=%d", response.StatusCode)
	}
}

func signedRawRequest(t *testing.T, baseURL, method, path string, payload []byte,
	principal string, key []byte, now time.Time, nonce string) *http.Request {
	t.Helper()
	timestamp := strconv.FormatInt(now.UTC().Unix(), 10)
	digest := sha256.Sum256(payload)
	canonical := canonicalAPIRequest(principal, method, path, timestamp, nonce,
		hex.EncodeToString(digest[:]))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(HeaderPrincipal, principal)
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestSignedStateResponseCannotBeModified(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	base := http.DefaultTransport
	tamper := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(request)
		if err != nil {
			return nil, err
		}
		var view StateView
		if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
			return nil, err
		}
		_ = response.Body.Close()
		view.Revision++
		payload, _ := json.Marshal(view)
		payload = append(payload, '\n')
		response.Body = io.NopCloser(bytes.NewReader(payload))
		response.ContentLength = int64(len(payload))
		return response, nil
	})
	client, err := NewClient(fixture.server.URL, Principal{
		ID: "controlplane-a", Role: "controlplane", Key: testControlKey,
	}, tamper, true)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return *fixture.now }
	if _, err := client.GetState(context.Background()); err == nil {
		t.Fatal("tampered signed response was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
