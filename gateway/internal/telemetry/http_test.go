package telemetry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type hijackTestWriter struct {
	header     http.Header
	connection net.Conn
}

func (writer *hijackTestWriter) Header() http.Header        { return writer.header }
func (*hijackTestWriter) Write(payload []byte) (int, error) { return len(payload), nil }
func (*hijackTestWriter) WriteHeader(int)                   {}
func (writer *hijackTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return writer.connection, bufio.NewReadWriter(
		bufio.NewReader(writer.connection), bufio.NewWriter(writer.connection)), nil
}

const testTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func testRuntime(t *testing.T, service string) (*Runtime, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return &Runtime{enabled: true, service: service, provider: provider,
		propagator: propagation.TraceContext{}, shutdown: provider.Shutdown}, recorder
}

func spanText(span sdktrace.ReadOnlySpan) string {
	return fmt.Sprintf("name=%s attributes=%v status=%v resource=%v",
		span.Name(), span.Attributes(), span.Status(), span.Resource())
}

func TestServerTraceUsesClosedMetadataAndOnlyTraceparent(t *testing.T) {
	runtime, recorder := testRuntime(t, "accountauthorization")
	handler := runtime.WrapHandler(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		if request.URL.Path != "/healthz" &&
			!oteltrace.SpanFromContext(request.Context()).SpanContext().IsValid() {
			t.Fatal("request context has no valid product trace")
		}
		writer.Header().Set("X-Internal-Secret", "response-secret")
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	request := httptest.NewRequest(http.MethodPost,
		"https://account.example/v1/companion-tokens/introspect?token=private-text",
		strings.NewReader("private prompt body"))
	request.Header.Set("Authorization", "Bearer private-token")
	request.Header.Set("traceparent", testTraceparent)
	request.Header.Set("tracestate", "vendor=private-state")
	request.Header.Set("baggage", "owner_id=private-owner")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	spans := recorder.Ended()
	if len(spans) != 1 || spans[0].Name() != "account.introspect" ||
		spans[0].Parent().TraceID().String() !=
			"4bf92f3577b34da6a3ce929d0e0e4736" ||
		!spans[0].Parent().IsRemote() || spans[0].Parent().TraceState().Len() != 0 {
		t.Fatalf("unexpected server trace lineage: %#v", spans)
	}
	text := spanText(spans[0])
	for _, forbidden := range []string{
		"private-text", "private prompt", "private-token", "private-state",
		"private-owner", "response-secret", "account.example",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("server span leaked %q: %s", forbidden, text)
		}
	}
	for _, expected := range []string{
		"{xiaozhi.operation account.introspect}",
		"{http.request.method POST}", "{http.response.status_code 503}",
		"{xiaozhi.result_class server_error}",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("server span missing %q: %s", expected, text)
		}
	}

	recorder.Reset()
	handler.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if len(recorder.Ended()) != 0 {
		t.Fatal("health probe created trace noise")
	}

	publicRuntime, publicRecorder := testRuntime(t, "agentproxy")
	publicRequest := httptest.NewRequest(http.MethodPost,
		"https://agent.example/v1/chat/completions", nil)
	publicRequest.Header.Set("traceparent", testTraceparent)
	publicRuntime.WrapHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), publicRequest)
	publicSpans := publicRecorder.Ended()
	if len(publicSpans) != 1 || publicSpans[0].Parent().IsValid() {
		t.Fatal("public edge accepted caller-controlled trace context")
	}
}

func TestWebSocketServerSpanEndsAtSuccessfulUpgrade(t *testing.T) {
	runtime, recorder := testRuntime(t, "gateway")
	serverConnection, peerConnection := net.Pipe()
	defer peerConnection.Close()
	writer := &hijackTestWriter{header: http.Header{}, connection: serverConnection}
	handler := runtime.WrapHandler(http.HandlerFunc(func(response http.ResponseWriter,
		request *http.Request) {
		connection, _, err := response.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		if spans := recorder.Ended(); len(spans) != 1 ||
			spans[0].Name() != "gateway.device" {
			t.Fatalf("upgrade did not end the server span: %#v", spans)
		}
		_ = connection.Close()
	}))
	handler.ServeHTTP(writer, httptest.NewRequest(
		http.MethodGet, "https://gateway.example/v1/device", nil))
	spans := recorder.Ended()
	if len(spans) != 1 || !strings.Contains(spanText(spans[0]),
		"{xiaozhi.result_class success}") || !strings.Contains(
		spanText(spans[0]), "{http.response.status_code 101}") {
		t.Fatalf("unexpected upgrade span: %#v", spans)
	}
}

func TestServerPanicEndsContentFreeErrorSpanAndRepanics(t *testing.T) {
	runtime, recorder := testRuntime(t, "agentproxy")
	handler := runtime.WrapHandler(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			panic("private panic body")
		}))
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("handler panic was swallowed")
			}
		}()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(
			http.MethodPost, "/v1/chat/completions", nil))
	}()
	spans := recorder.Ended()
	if len(spans) != 1 || !strings.Contains(spanText(spans[0]),
		"{xiaozhi.result_class server_error}") || strings.Contains(
		spanText(spans[0]), "private panic body") {
		t.Fatalf("unexpected panic span: %#v", spans)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClientTracePropagatesOnlyTraceparentAndEndsWithBody(t *testing.T) {
	runtime, recorder := testRuntime(t, "agentproxy")
	var observed http.Header
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		observed = request.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     http.Header{"X-Provider": []string{"private-provider-value"}},
			Body:       io.NopCloser(strings.NewReader("private provider body")),
			Request:    request,
		}, nil
	})
	transport, err := runtime.WrapTransport("agent.provider", base)
	if err != nil {
		t.Fatal(err)
	}
	ctx, parent := runtime.tracer().Start(context.Background(), "test-parent")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://provider.example/v1/chat/completions?secret=query",
		strings.NewReader("private request body"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer provider-secret")
	request.Header.Set("traceparent", testTraceparent)
	request.Header.Set("tracestate", "vendor=secret")
	request.Header.Set("baggage", "owner=secret")
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Get("traceparent") != "" ||
		observed.Get("tracestate") != "" || observed.Get("baggage") != "" ||
		observed.Get("Authorization") != "Bearer provider-secret" {
		t.Fatalf("unsafe propagation headers: %#v", observed)
	}
	if len(recorder.Ended()) != 0 {
		t.Fatal("client span ended before response body")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	spans := recorder.Ended()
	if len(spans) != 1 || spans[0].Name() != "agent.provider" {
		t.Fatalf("unexpected client spans: %#v", spans)
	}
	text := spanText(spans[0])
	for _, forbidden := range []string{
		"provider.example", "private request", "provider-secret", "secret=query",
		"private provider", "private-provider-value", "vendor=secret", "owner=secret",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("client span leaked %q: %s", forbidden, text)
		}
	}
	parent.End()
	internal, err := runtime.WrapTransport("generation.coordinator", base)
	if err != nil {
		t.Fatal(err)
	}
	internalRequest := httptest.NewRequest(http.MethodGet,
		"https://generation.example/v1/generations/state", nil).WithContext(ctx)
	internalResponse, err := internal.RoundTrip(internalRequest)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Get("traceparent") == "" {
		t.Fatal("internal service trace context was not propagated")
	}
	if err := internalResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.WrapTransport("dynamic."+"private-content", base); err == nil {
		t.Fatal("unregistered outbound operation was accepted")
	}
}

func TestClientTransportErrorDoesNotRecordErrorText(t *testing.T) {
	runtime, recorder := testRuntime(t, "gateway")
	transport, err := runtime.WrapTransport("speech.stt",
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("private-host private-token private transcript")
		}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"https://private-host/v1/stt?text=private-transcript", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("transport error was lost")
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("unexpected error spans: %#v", spans)
	}
	text := spanText(spans[0])
	if strings.Contains(text, "private-host") || strings.Contains(text, "private-token") ||
		strings.Contains(text, "private transcript") {
		t.Fatalf("transport error text leaked into span: %s", text)
	}
}

func TestClientInvalidResponseEndsWithoutPanicOrContent(t *testing.T) {
	runtime, recorder := testRuntime(t, "agentproxy")
	transport, err := runtime.WrapTransport("agent.provider",
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"https://provider.example/private", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("invalid transport response was accepted")
	}
	spans := recorder.Ended()
	if len(spans) != 1 || !strings.Contains(spanText(spans[0]),
		"{xiaozhi.result_class transport_error}") {
		t.Fatalf("unexpected invalid-response spans: %#v", spans)
	}
}

func TestServerOperationsAreClosedAndDoNotIncludeDynamicIdentifiers(t *testing.T) {
	tests := []struct {
		service, method, path, expected string
	}{
		{"controlplane", http.MethodGet,
			"/v1/devices/device-private/action-consents/pending",
			"controlplane.consent_pending"},
		{"controlplane", http.MethodPost,
			"/v1/devices/device-private/action-consents/challenge-private/decision",
			"controlplane.consent_decision"},
		{"firmwareorigin", http.MethodGet, "/private-release/firmware.bin",
			"firmware.download"},
		{"gateway", http.MethodPost, "/private-text", ""},
	}
	for _, test := range tests {
		operation, ok := serverOperation(test.service, test.method, test.path)
		expectedOK := test.expected != ""
		if ok != expectedOK || operation != test.expected ||
			strings.Contains(operation, "private") {
			t.Fatalf("unsafe operation for %#v: %q ok=%t", test, operation, ok)
		}
	}
	for _, path := range []string{
		"/v1/devices/device-private/action-consents/extra/pending",
		"/v1/devices/device-private/action-consents/challenge-private/extra/decision",
		"/prefix/v1/devices/device-private/action-consents/pending",
	} {
		operation, ok := serverOperation("controlplane", http.MethodGet, path)
		if ok || operation != "" {
			t.Fatalf("malformed dynamic route was classified as a product operation: %s", path)
		}
	}
}
