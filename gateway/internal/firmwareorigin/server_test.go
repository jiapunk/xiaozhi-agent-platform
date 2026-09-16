package firmwareorigin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

var testOriginKey = []byte("ota-origin-key-0123456789abcdef012345")

func testOrigin(t *testing.T) (*Server, *auth.Issuer, []byte, string, string) {
	return testOriginWithIdentity(t, nil)
}

func testOriginWithIdentity(t *testing.T,
	identity *provisioning.Registry) (*Server, *auth.Issuer, []byte, string, string) {
	t.Helper()
	image := []byte(strings.Repeat("firmware-image-", 128))
	catalog, imagePath, hash := writeCatalogFixture(t, image)
	verifier, err := auth.NewVerifierForAudience(
		testOriginKey, 15*time.Minute, auth.OTAAudience)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := auth.NewIssuerForAudience(
		testOriginKey, 5*time.Minute, auth.OTAAudience)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Catalog: catalog, Verifier: verifier,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxConcurrent:    4,
		PublicAuthority:  "updates.example",
		GenerationGate:   generation.StaticGate(true),
		IdentityRegistry: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, issuer, image, imagePath, hash
}

func originAccessSnapshot(t *testing.T, revision uint64, disabled bool,
	now time.Time) *provisioning.Snapshot {
	t.Helper()
	seed := sha256.Sum256([]byte("firmware-origin-access-snapshot-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	unsigned := fmt.Sprintf(
		`{"version":2,"revision":%d,"purpose":"access",`+
			`"issued_at":"%s","valid_until":"%s",`+
			`"devices":[{"device_id":"device-1","disabled":%t}]}`,
		revision, now.Add(-time.Minute).Format(time.RFC3339),
		now.Add(10*time.Minute).Format(time.RFC3339), disabled)
	signed, err := provisioning.SignRegistrySnapshot(strings.NewReader(unsigned),
		"origin-access-test", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provisioning.ParseSignedRegistrySnapshot(
		strings.NewReader(string(signed)), publicKey, "origin-access-test", now)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func originRequest(t *testing.T, target, token string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Host = "updates.example"
	request.Header.Set("Accept", "application/octet-stream")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

func issueOriginToken(t *testing.T, issuer *auth.Issuer,
	releaseID, hash string) string {
	t.Helper()
	token, _, err := issuer.IssueForRelease("device-1", releaseID, hash)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestOriginStreamsExactAuthorizedImmutableImage(t *testing.T) {
	server, issuer, image, _, hash := testOrigin(t)
	token := issueOriginToken(t, issuer, "box3-development-0015", hash)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, originRequest(t,
		"https://updates.example/firmware/box3/0015.bin", token))
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/octet-stream" ||
		response.Header().Get("Content-Length") != strconv.Itoa(len(image)) ||
		response.Header().Get("ETag") != `"sha256:`+hash+`"` ||
		response.Header().Get("Cache-Control") != "private, no-store, max-age=0" ||
		!bytes.Equal(response.Body.Bytes(), image) {
		t.Fatalf("unexpected firmware response: status=%d headers=%v size=%d",
			response.Code, response.Header(), response.Body.Len())
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_firmware_origin_requests_total 1",
		"xiaozhi_firmware_origin_served_total 1",
		"xiaozhi_firmware_origin_bytes_served_total " + strconv.Itoa(len(image)),
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected,
				metrics.Body.String())
		}
	}
}

func TestOriginRejectsWrongAudienceReleaseHashAndUnknownObject(t *testing.T) {
	server, issuer, _, _, hash := testOrigin(t)
	cases := map[string]struct {
		target string
		token  string
		status int
	}{
		"missing-token": {
			target: "/firmware/box3/0015.bin", status: http.StatusUnauthorized,
		},
		"wrong-release": {
			target: "/firmware/box3/0015.bin",
			token:  issueOriginToken(t, issuer, "box3-development-0016", hash),
			status: http.StatusUnauthorized,
		},
		"wrong-hash": {
			target: "/firmware/box3/0015.bin",
			token: issueOriginToken(t, issuer, "box3-development-0015",
				strings.Repeat("b", 64)),
			status: http.StatusUnauthorized,
		},
		"unknown-object": {
			target: "/firmware/box3/9999.bin",
			token:  issueOriginToken(t, issuer, "box3-development-0015", hash),
			status: http.StatusNotFound,
		},
	}
	voiceIssuer, err := auth.NewIssuerForAudience(
		testOriginKey, 5*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	voiceToken, _, err := voiceIssuer.IssueOwned(
		"device-1", "user-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 1)
	if err != nil {
		t.Fatal(err)
	}
	cases["voice-audience"] = struct {
		target string
		token  string
		status int
	}{
		target: "/firmware/box3/0015.bin", token: voiceToken,
		status: http.StatusUnauthorized,
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response,
				originRequest(t, test.target, test.token))
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code,
					response.Body.String())
			}
		})
	}
}

func TestOriginRejectsRangeConditionalQueryBodyAndDuplicateHeaders(t *testing.T) {
	server, issuer, _, _, hash := testOrigin(t)
	token := issueOriginToken(t, issuer, "box3-development-0015", hash)
	requests := map[string]*http.Request{
		"query":          originRequest(t, "/firmware/box3/0015.bin?x=1", token),
		"range":          originRequest(t, "/firmware/box3/0015.bin", token),
		"conditional":    originRequest(t, "/firmware/box3/0015.bin", token),
		"wrong-accept":   originRequest(t, "/firmware/box3/0015.bin", token),
		"duplicate-auth": originRequest(t, "/firmware/box3/0015.bin", token),
		"wrong-host":     originRequest(t, "/firmware/box3/0015.bin", token),
		"body": httptest.NewRequest(http.MethodGet,
			"/firmware/box3/0015.bin", strings.NewReader("body")),
	}
	requests["range"].Header.Set("Range", "bytes=0-31")
	requests["conditional"].Header.Set("If-None-Match", `"anything"`)
	requests["wrong-accept"].Header.Set("Accept", "*/*")
	requests["duplicate-auth"].Header.Add("Authorization", "Bearer "+token)
	requests["body"].Header.Set("Accept", "application/octet-stream")
	requests["body"].Header.Set("Authorization", "Bearer "+token)
	requests["body"].Host = "updates.example"
	requests["wrong-host"].Host = "attacker.example"
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			expected := http.StatusBadRequest
			if name == "duplicate-auth" {
				expected = http.StatusUnauthorized
			}
			if response.Code != expected {
				t.Fatalf("status=%d body=%s", response.Code,
					response.Body.String())
			}
		})
	}
}

func TestOriginRehashesBeforeFirstByteAndReadinessDetectsMissingObject(t *testing.T) {
	server, issuer, image, imagePath, hash := testOrigin(t)
	token := issueOriginToken(t, issuer, "box3-development-0015", hash)
	if err := os.Chmod(imagePath, 0o644); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Repeat([]byte{'x'}, len(image))
	if err := os.WriteFile(imagePath, tampered, 0o444); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, originRequest(t,
		"/firmware/box3/0015.bin", token))
	if response.Code != http.StatusServiceUnavailable ||
		bytes.Contains(response.Body.Bytes(), tampered[:64]) {
		t.Fatalf("tampered response status=%d size=%d",
			response.Code, response.Body.Len())
	}
	if err := os.Remove(imagePath); err != nil {
		t.Fatal(err)
	}
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status=%d body=%s", ready.Code,
			ready.Body.String())
	}
}

func TestOriginRequiresOTAEndpointVerifier(t *testing.T) {
	image := []byte(strings.Repeat("firmware-image-", 128))
	catalog, _, _ := writeCatalogFixture(t, image)
	voiceVerifier, err := auth.NewVerifierForAudience(
		testOriginKey, 15*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{
		Catalog: catalog, Verifier: voiceVerifier,
		MaxConcurrent: 1, PublicAuthority: "updates.example",
		GenerationGate: generation.StaticGate(true),
	}); err == nil {
		t.Fatal("firmware origin accepted a voice-audience verifier")
	}
}

type blockingResponseWriter struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (writer *blockingResponseWriter) Header() http.Header {
	return writer.header
}

func (writer *blockingResponseWriter) WriteHeader(status int) {
	writer.status = status
}

func (writer *blockingResponseWriter) Write(payload []byte) (int, error) {
	writer.once.Do(func() { close(writer.started) })
	<-writer.release
	return writer.body.Write(payload)
}

func TestOriginAllowsOnlyOneActiveDownloadPerDevice(t *testing.T) {
	server, issuer, image, _, hash := testOrigin(t)
	token := issueOriginToken(t, issuer, "box3-development-0015", hash)
	blocked := &blockingResponseWriter{
		header: make(http.Header), started: make(chan struct{}),
		release: make(chan struct{}),
	}
	firstRequest := originRequest(t, "/firmware/box3/0015.bin", token)
	done := make(chan struct{})
	go func() {
		server.Handler().ServeHTTP(blocked, firstRequest)
		close(done)
	}()
	select {
	case <-blocked.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first firmware download did not start")
	}
	second := httptest.NewRecorder()
	server.Handler().ServeHTTP(second, originRequest(t,
		"/firmware/box3/0015.bin", token))
	if second.Code != http.StatusTooManyRequests ||
		second.Header().Get("Retry-After") != "5" {
		t.Fatalf("parallel device download status=%d headers=%v",
			second.Code, second.Header())
	}
	close(blocked.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first firmware download did not finish")
	}
	if blocked.status != http.StatusOK || !bytes.Equal(blocked.body.Bytes(), image) {
		t.Fatalf("first firmware response status=%d size=%d",
			blocked.status, blocked.body.Len())
	}
}

func TestOriginGenerationGateBlocksBeforeAuthorizationAndReadiness(t *testing.T) {
	server, issuer, image, _, hash := testOrigin(t)
	token := issueOriginToken(t, issuer, "box3-development-0015", hash)
	request := originRequest(t, "/firmware/box3/0015.bin", token)
	server.config.GenerationGate = generation.StaticGate(false)
	blocked := httptest.NewRecorder()
	server.Handler().ServeHTTP(blocked, request)
	if blocked.Code != http.StatusServiceUnavailable ||
		blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("blocked origin status=%d headers=%v body=%s",
			blocked.Code, blocked.Header(), blocked.Body.String())
	}
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("blocked origin readiness status=%d", ready.Code)
	}
	server.config.GenerationGate = generation.StaticGate(true)
	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, request)
	if allowed.Code != http.StatusOK || !bytes.Equal(allowed.Body.Bytes(), image) {
		t.Fatalf("origin did not recover status=%d size=%d",
			allowed.Code, allowed.Body.Len())
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_firmware_origin_generation_blocked_total 1") {
		t.Fatalf("missing generation metric: %s", metrics.Body.String())
	}
}

type deadlineBlockingResponseWriter struct {
	header   http.Header
	status   int
	started  chan struct{}
	release  chan struct{}
	start    sync.Once
	deadline sync.Once
	aborted  atomic.Bool
}

func (writer *deadlineBlockingResponseWriter) Header() http.Header {
	return writer.header
}

func (writer *deadlineBlockingResponseWriter) WriteHeader(status int) {
	writer.status = status
}

func (writer *deadlineBlockingResponseWriter) Write(_ []byte) (int, error) {
	writer.start.Do(func() { close(writer.started) })
	<-writer.release
	if writer.aborted.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	return 0, io.ErrShortWrite
}

func (writer *deadlineBlockingResponseWriter) SetWriteDeadline(time.Time) error {
	writer.aborted.Store(true)
	writer.deadline.Do(func() { close(writer.release) })
	return nil
}

func TestIdentityRevokeInterruptsFirmwareStreamAndRejectsOldToken(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	identity, err := provisioning.NewRegistryFromSnapshot(
		originAccessSnapshot(t, 60, false, clock), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	server, issuer, _, _, hash := testOriginWithIdentity(t, identity)
	token := issueOriginToken(t, issuer, "box3-development-0015", hash)
	blocked := &deadlineBlockingResponseWriter{
		header: make(http.Header), started: make(chan struct{}),
		release: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		server.Handler().ServeHTTP(blocked,
			originRequest(t, "/firmware/box3/0015.bin", token))
		close(done)
	}()
	select {
	case <-blocked.started:
	case <-time.After(5 * time.Second):
		t.Fatal("firmware stream did not start")
	}
	if changed, err := identity.ApplySnapshot(
		originAccessSnapshot(t, 61, true, clock)); err != nil || !changed {
		t.Fatalf("apply identity revoke: changed=%v err=%v", changed, err)
	}
	if canceled := server.ReconcileIdentity(); canceled != 1 {
		t.Fatalf("canceled firmware streams=%d", canceled)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("identity revoke did not interrupt firmware writer")
	}
	if blocked.status != http.StatusOK || !blocked.aborted.Load() {
		t.Fatalf("stream revoke status=%d aborted=%v",
			blocked.status, blocked.aborted.Load())
	}
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied,
		originRequest(t, "/firmware/box3/0015.bin", token))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("old OTA token status=%d body=%s",
			denied.Code, denied.Body.String())
	}
	unknown := httptest.NewRecorder()
	server.Handler().ServeHTTP(unknown,
		originRequest(t, "/firmware/box3/unknown.bin", token))
	if unknown.Code != http.StatusUnauthorized {
		t.Fatalf("revoked unknown-object token status=%d", unknown.Code)
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_firmware_origin_identity_rejected_total 1",
		"xiaozhi_firmware_origin_identity_canceled_total 1",
		"xiaozhi_firmware_origin_stream_failed_total 1",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected, metrics.Body.String())
		}
	}
}

func TestExpiredIdentityFailsFirmwareOriginReadiness(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	identity, err := provisioning.NewRegistryFromSnapshot(
		originAccessSnapshot(t, 70, false, clock), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	server, _, _, _, _ := testOriginWithIdentity(t, identity)
	clock = clock.Add(11 * time.Minute)
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired identity readiness=%d", ready.Code)
	}
}
