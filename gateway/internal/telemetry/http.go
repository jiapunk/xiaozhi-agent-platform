package telemetry

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var outboundOperations = map[string]bool{
	// Third-party providers receive no product trace context. Their local spans
	// remain useful without disclosing a cross-request correlation identifier.
	"agent.provider":          false,
	"companion.introspection": true,
	"companion.wake":          true,
	"factory.signer":          true,
	"generation.coordinator":  true,
	"push.apns":               false,
	"push.fcm":                false,
	"push.oauth":              false,
	"speech.stt":              true,
	"speech.tts":              true,
}

var acceptInboundTraceContext = map[string]bool{
	"accountauthorization":  true,
	"generationcoordinator": true,
}

var serverOperations = map[string]map[string]string{
	"gateway": {
		"GET /v1/device":   "gateway.device",
		"POST /v1/session": "gateway.session",
	},
	"controlplane": {
		"POST /v1/time":                             "controlplane.time",
		"POST /v1/session":                          "controlplane.voice_token",
		"POST /v1/agent-token":                      "controlplane.agent_token",
		"POST /v1/ota/offer":                        "controlplane.ota_offer",
		"POST /v1/device-claim/app":                 "controlplane.claim_app",
		"POST /v1/device-claim/device":              "controlplane.claim_device",
		"GET /v1/device-claim/status":               "controlplane.claim_status",
		"POST /v1/device-ownership/release":         "controlplane.owner_release",
		"POST /v1/action-consents/device/challenge": "controlplane.consent_challenge",
		"POST /v1/action-consents/device/result":    "controlplane.consent_result",
	},
	"agentproxy": {
		"POST /v1/chat/completions": "agentproxy.completion",
	},
	"generationcoordinator": {
		"GET /v1/generations/state":    "generation.state",
		"POST /v1/generations/publish": "generation.publish",
		"POST /v1/generations/abort":   "generation.abort",
		"POST /v1/generations/ack":     "generation.ack",
	},
	"accountauthorization": {
		"POST /v1/companion-tokens/introspect":                 "account.introspect",
		"POST /v1/companion-notifications/action-consent-wake": "account.wake",
	},
	"factorytimeauthority": {
		"POST /v1/factory/trusted-time": "factory.time",
	},
}

func (runtime *Runtime) WrapHandler(handler http.Handler) http.Handler {
	if handler == nil || runtime == nil || !runtime.enabled {
		return handler
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		operation, traceRequest := serverOperation(runtime.service,
			request.Method, request.URL.Path)
		if !traceRequest {
			handler.ServeHTTP(writer, request)
			return
		}
		ctx := request.Context()
		if acceptInboundTraceContext[runtime.service] {
			carrier := propagation.MapCarrier{}
			if parent := request.Header.Get("traceparent"); parent != "" {
				carrier.Set("traceparent", parent)
			}
			ctx = runtime.propagator.Extract(ctx, carrier)
		}
		ctx, span := runtime.tracer().Start(ctx, operation,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("xiaozhi.operation", operation),
				attribute.String("http.request.method", safeMethod(request.Method))))
		var endOnce sync.Once
		finish := func(code int) {
			endOnce.Do(func() {
				span.SetAttributes(
					attribute.Int("http.response.status_code", code),
					attribute.String("xiaozhi.result_class", statusClass(code)))
				if code >= 500 {
					span.SetStatus(codes.Error, "")
				}
				span.End()
			})
		}
		status := &statusWriter{ResponseWriter: writer,
			onHijack: func() { finish(http.StatusSwitchingProtocols) }}
		defer func() {
			if recovered := recover(); recovered != nil {
				finish(http.StatusInternalServerError)
				panic(recovered)
			}
		}()
		handler.ServeHTTP(status, request.WithContext(ctx))
		code := status.status
		if code == 0 {
			code = http.StatusOK
		}
		finish(code)
	})
}

func (runtime *Runtime) WrapTransport(operation string,
	base http.RoundTripper) (http.RoundTripper, error) {
	propagate, ok := outboundOperations[operation]
	if !ok {
		return nil, errors.New("telemetry outbound operation is invalid")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	if runtime == nil || !runtime.enabled {
		return base, nil
	}
	return &traceTransport{runtime: runtime, operation: operation,
		base: base, propagate: propagate}, nil
}

type traceTransport struct {
	runtime   *Runtime
	operation string
	base      http.RoundTripper
	propagate bool
}

func (transport *traceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, span := transport.runtime.tracer().Start(request.Context(),
		transport.operation, trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("xiaozhi.operation", transport.operation),
			attribute.String("http.request.method", safeMethod(request.Method))))
	clone := request.Clone(ctx)
	clone.Header.Del("baggage")
	clone.Header.Del("tracestate")
	clone.Header.Del("traceparent")
	if transport.propagate {
		carrier := propagation.MapCarrier{}
		transport.runtime.propagator.Inject(ctx, carrier)
		if parent := carrier.Get("traceparent"); parent != "" {
			clone.Header.Set("traceparent", parent)
		}
	}
	response, err := transport.base.RoundTrip(clone)
	if err != nil {
		span.SetAttributes(attribute.String("xiaozhi.result_class", "transport_error"))
		span.SetStatus(codes.Error, "")
		span.End()
		return nil, err
	}
	if response == nil || response.Body == nil {
		span.SetAttributes(attribute.String(
			"xiaozhi.result_class", "transport_error"))
		span.SetStatus(codes.Error, "")
		span.End()
		return nil, errors.New("telemetry transport returned an invalid response")
	}
	span.SetAttributes(
		attribute.Int("http.response.status_code", response.StatusCode),
		attribute.String("xiaozhi.result_class", statusClass(response.StatusCode)))
	if response.StatusCode >= 500 {
		span.SetStatus(codes.Error, "")
	}
	response.Body = &spanBody{ReadCloser: response.Body, span: span}
	return response, nil
}

type spanBody struct {
	io.ReadCloser
	span trace.Span
	once sync.Once
}

func (body *spanBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	if err != nil {
		body.end()
	}
	return count, err
}

func (body *spanBody) Close() error {
	err := body.ReadCloser.Close()
	body.end()
	return err
}

func (body *spanBody) end() {
	body.once.Do(func() { body.span.End() })
}

type statusWriter struct {
	http.ResponseWriter
	status   int
	onHijack func()
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(payload []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(payload)
}

func (writer *statusWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := writer.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	connection, buffered, err := hijacker.Hijack()
	if err == nil {
		writer.status = http.StatusSwitchingProtocols
		if writer.onHijack != nil {
			writer.onHijack()
		}
	}
	return connection, buffered, err
}

func (writer *statusWriter) Flush() {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	if flusher, ok := writer.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (writer *statusWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := writer.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (writer *statusWriter) ReadFrom(reader io.Reader) (int64, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	if readerFrom, ok := writer.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(reader)
	}
	return io.Copy(struct{ io.Writer }{writer.ResponseWriter}, reader)
}

func safeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost:
		return method
	default:
		return "OTHER"
	}
}

func statusClass(status int) string {
	switch {
	case status == http.StatusSwitchingProtocols ||
		status >= 200 && status < 300:
		return "success"
	case status >= 400 && status < 500:
		return "client_error"
	case status >= 500:
		return "server_error"
	default:
		return "other"
	}
}

func serverOperation(service, method, path string) (string, bool) {
	if method == http.MethodGet &&
		(path == "/healthz" || path == "/readyz" || path == "/metrics") {
		return "", false
	}
	key := method + " " + path
	if operation := serverOperations[service][key]; operation != "" {
		return operation, true
	}
	if service == "firmwareorigin" && method == http.MethodGet {
		return "firmware.download", true
	}
	if service == "controlplane" {
		segments := strings.Split(path, "/")
		if method == http.MethodGet && len(segments) == 6 &&
			segments[1] == "v1" && segments[2] == "devices" &&
			segments[3] != "" && segments[4] == "action-consents" &&
			segments[5] == "pending" {
			return "controlplane.consent_pending", true
		}
		if method == http.MethodPost && len(segments) == 7 &&
			segments[1] == "v1" && segments[2] == "devices" &&
			segments[3] != "" && segments[4] == "action-consents" &&
			segments[5] != "" && segments[6] == "decision" {
			return "controlplane.consent_decision", true
		}
	}
	return "", false
}
