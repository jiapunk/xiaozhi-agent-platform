package firmwareorigin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/identityaccess"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

type Config struct {
	Catalog          *Catalog
	Verifier         *auth.Verifier
	Logger           *slog.Logger
	MaxConcurrent    int
	PublicAuthority  string
	GenerationGate   generation.ServingGate
	IdentityRegistry *provisioning.Registry
}

type Server struct {
	config      Config
	mux         *http.ServeMux
	concurrency chan struct{}
	devicesMu   sync.Mutex
	devices     map[string]struct{}
	stats       metrics
	identity    *identityaccess.Tracker
}

type metrics struct {
	requests          atomic.Uint64
	served            atomic.Uint64
	authRejected      atomic.Uint64
	policyRejected    atomic.Uint64
	notFound          atomic.Uint64
	integrityFailed   atomic.Uint64
	busy              atomic.Uint64
	deviceBusy        atomic.Uint64
	streamFailed      atomic.Uint64
	bytesServed       atomic.Uint64
	generationBlocked atomic.Uint64
	identityRejected  atomic.Uint64
	identityCanceled  atomic.Uint64
}

func New(config Config) (*Server, error) {
	if config.Catalog == nil ||
		!config.Verifier.AcceptsAudience(auth.OTAAudience) ||
		config.Catalog.Ready() != nil || config.MaxConcurrent < 1 ||
		config.MaxConcurrent > 10000 || !validAuthority(config.PublicAuthority) ||
		config.GenerationGate == nil {
		return nil, fmt.Errorf("firmware origin dependencies are invalid")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	server := &Server{
		config: config, concurrency: make(chan struct{}, config.MaxConcurrent),
		devices: make(map[string]struct{}),
	}
	if config.IdentityRegistry != nil {
		identity, err := identityaccess.New(config.IdentityRegistry)
		if err != nil {
			return nil, err
		}
		server.identity = identity
	}
	server.mux = http.NewServeMux()
	server.mux.HandleFunc("GET /healthz", server.health)
	server.mux.HandleFunc("GET /readyz", server.ready)
	server.mux.HandleFunc("GET /metrics", server.metrics)
	server.mux.HandleFunc("GET /", server.download)
	return server, nil
}

func (server *Server) Handler() http.Handler { return server.mux }

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, `{"status":"ok"}`)
}

func (server *Server) ready(writer http.ResponseWriter, _ *http.Request) {
	if server.identity != nil && !server.identity.Ready() {
		http.Error(writer, "device identity unavailable", http.StatusServiceUnavailable)
		return
	}
	if !server.config.GenerationGate.Ready() {
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := server.config.Catalog.Ready(); err != nil {
		http.Error(writer, "firmware catalog unavailable",
			http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, `{"status":"ready"}`)
}

func (server *Server) download(writer http.ResponseWriter,
	request *http.Request) {
	setSecurityHeaders(writer)
	server.stats.requests.Add(1)
	if !server.config.GenerationGate.AllowOTA() {
		server.stats.generationBlocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	if !validDownloadRequest(request, server.config.PublicAuthority) {
		server.stats.policyRejected.Add(1)
		http.Error(writer, "invalid firmware request", http.StatusBadRequest)
		return
	}
	authorization, ok := singleHeader(request, "Authorization")
	if !ok {
		server.rejectAuthorization(writer)
		return
	}
	object, found := server.config.Catalog.Lookup(request.URL.Path)
	if !found {
		claims, err := server.config.Verifier.VerifyAuthorization(authorization)
		if err != nil || (server.identity != nil &&
			!server.identity.Allowed(claims.DeviceID)) {
			server.rejectAuthorization(writer)
			return
		}
		server.stats.notFound.Add(1)
		http.Error(writer, "firmware not found", http.StatusNotFound)
		return
	}
	claims, err := server.config.Verifier.VerifyAuthorizationForRelease(
		authorization, object.ReleaseID, object.ImageSHA256)
	if err != nil {
		server.rejectAuthorization(writer)
		return
	}
	streamContext := request.Context()
	finishIdentity := func() {}
	if server.identity != nil {
		controller := http.NewResponseController(writer)
		var allowed bool
		streamContext, finishIdentity, allowed = server.identity.Start(
			request.Context(), claims.DeviceID, func() {
				_ = controller.SetWriteDeadline(time.Now())
			})
		if !allowed {
			server.rejectIdentity(writer)
			return
		}
		defer finishIdentity()
	}
	if !server.acquireDevice(claims.DeviceID) {
		server.stats.deviceBusy.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "firmware download already active",
			http.StatusTooManyRequests)
		return
	}
	defer server.releaseDevice(claims.DeviceID)
	select {
	case server.concurrency <- struct{}{}:
		defer func() { <-server.concurrency }()
	default:
		server.stats.busy.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "firmware origin busy",
			http.StatusServiceUnavailable)
		return
	}

	file, err := object.OpenVerified()
	if err != nil {
		server.stats.integrityFailed.Add(1)
		server.config.Logger.Error("firmware object rejected",
			"release_id", object.ReleaseID,
			"error_class", "object_integrity_failed")
		http.Error(writer, "firmware unavailable",
			http.StatusServiceUnavailable)
		return
	}
	defer file.Close()
	if !server.config.GenerationGate.AllowOTA() {
		server.stats.generationBlocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		http.Error(writer, "OTA generation unavailable", http.StatusServiceUnavailable)
		return
	}
	if server.identityRevoked(streamContext, claims.DeviceID) {
		server.rejectIdentity(writer)
		return
	}

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.FormatInt(object.ImageSize, 10))
	writer.Header().Set("ETag", `"sha256:`+object.ImageSHA256+`"`)
	writer.Header().Set("Accept-Ranges", "none")
	writer.WriteHeader(http.StatusOK)
	written, copyErr := copyExactContext(streamContext, writer, file,
		object.ImageSize)
	if copyErr != nil || written != object.ImageSize {
		server.stats.streamFailed.Add(1)
		server.config.Logger.Warn("firmware stream interrupted",
			"device_id", claims.DeviceID,
			"release_id", object.ReleaseID,
			"error_class", "stream_interrupted")
		return
	}
	server.stats.served.Add(1)
	server.stats.bytesServed.Add(uint64(written))
}

func (server *Server) identityRevoked(ctx context.Context, deviceID string) bool {
	return server.identity != nil &&
		(identityaccess.Revoked(ctx) || !server.identity.Allowed(deviceID))
}

func (server *Server) ReconcileIdentity() int {
	if server == nil || server.identity == nil {
		return 0
	}
	canceled := server.identity.Reconcile()
	server.stats.identityCanceled.Add(uint64(canceled))
	return canceled
}

func copyExactContext(ctx context.Context, writer io.Writer,
	reader io.Reader, expected int64) (int64, error) {
	if ctx == nil || writer == nil || reader == nil || expected < 0 {
		return 0, fmt.Errorf("invalid context copy")
	}
	buffer := make([]byte, 32*1024)
	var written int64
	for written < expected {
		select {
		case <-ctx.Done():
			return written, context.Cause(ctx)
		default:
		}
		remaining := expected - written
		chunk := buffer
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		read, readErr := reader.Read(chunk)
		if read > 0 {
			select {
			case <-ctx.Done():
				return written, context.Cause(ctx)
			default:
			}
			output, writeErr := writer.Write(chunk[:read])
			written += int64(output)
			if writeErr != nil {
				return written, writeErr
			}
			if output != read {
				return written, io.ErrShortWrite
			}
			select {
			case <-ctx.Done():
				return written, context.Cause(ctx)
			default:
			}
		}
		if readErr != nil {
			if readErr == io.EOF && written == expected {
				return written, nil
			}
			return written, readErr
		}
		if read == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func (server *Server) acquireDevice(deviceID string) bool {
	server.devicesMu.Lock()
	defer server.devicesMu.Unlock()
	if _, exists := server.devices[deviceID]; exists {
		return false
	}
	server.devices[deviceID] = struct{}{}
	return true
}

func (server *Server) releaseDevice(deviceID string) {
	server.devicesMu.Lock()
	delete(server.devices, deviceID)
	server.devicesMu.Unlock()
}

func validDownloadRequest(request *http.Request, publicAuthority string) bool {
	if request == nil || request.URL == nil || request.Method != http.MethodGet ||
		request.Host != publicAuthority ||
		request.URL.RawQuery != "" || request.URL.RawPath != "" ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	accept, acceptOK := singleHeader(request, "Accept")
	if !acceptOK || accept != "application/octet-stream" {
		return false
	}
	for _, name := range []string{
		"Range", "If-Range", "If-Match", "If-None-Match",
		"If-Modified-Since", "If-Unmodified-Since",
	} {
		if len(request.Header.Values(name)) != 0 {
			return false
		}
	}
	return true
}

func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func (server *Server) rejectAuthorization(writer http.ResponseWriter) {
	server.stats.authRejected.Add(1)
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func (server *Server) rejectIdentity(writer http.ResponseWriter) {
	server.stats.identityRejected.Add(1)
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func (server *Server) metrics(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(writer,
		"xiaozhi_firmware_origin_requests_total %d\n"+
			"xiaozhi_firmware_origin_served_total %d\n"+
			"xiaozhi_firmware_origin_auth_rejected_total %d\n"+
			"xiaozhi_firmware_origin_policy_rejected_total %d\n"+
			"xiaozhi_firmware_origin_not_found_total %d\n"+
			"xiaozhi_firmware_origin_integrity_failed_total %d\n"+
			"xiaozhi_firmware_origin_busy_total %d\n"+
			"xiaozhi_firmware_origin_device_busy_total %d\n"+
			"xiaozhi_firmware_origin_stream_failed_total %d\n"+
			"xiaozhi_firmware_origin_bytes_served_total %d\n"+
			"xiaozhi_firmware_origin_generation_blocked_total %d\n"+
			"xiaozhi_firmware_origin_identity_rejected_total %d\n"+
			"xiaozhi_firmware_origin_identity_canceled_total %d\n",
		server.stats.requests.Load(), server.stats.served.Load(),
		server.stats.authRejected.Load(), server.stats.policyRejected.Load(),
		server.stats.notFound.Load(), server.stats.integrityFailed.Load(),
		server.stats.busy.Load(), server.stats.deviceBusy.Load(),
		server.stats.streamFailed.Load(),
		server.stats.bytesServed.Load(), server.stats.generationBlocked.Load(),
		server.stats.identityRejected.Load(), server.stats.identityCanceled.Load())
}

func setSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "private, no-store, max-age=0")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
}

func writeJSON(writer http.ResponseWriter, status int, payload string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, payload+"\n")
}
