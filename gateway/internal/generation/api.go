package generation

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	HeaderPrincipal         = "X-Xiaozhi-Generation-Principal"
	HeaderTimestamp         = "X-Xiaozhi-Generation-Timestamp"
	HeaderNonce             = "X-Xiaozhi-Generation-Nonce"
	HeaderSignature         = "X-Xiaozhi-Generation-Signature"
	HeaderResponseSignature = "X-Xiaozhi-Generation-Response-Signature"

	pathState   = "/v1/generations/state"
	pathPublish = "/v1/generations/publish"
	pathAbort   = "/v1/generations/abort"
	pathAck     = "/v1/generations/ack"

	maximumAPIBytes = 16 * 1024
)

type StateView struct {
	Schema           int               `json:"schema"`
	Revision         uint64            `json:"revision"`
	RecordSHA256     string            `json:"record_sha256"`
	Phase            string            `json:"phase"`
	Active           Generation        `json:"active"`
	Pending          *Generation       `json:"pending"`
	RequiredReplicas []ReplicaRef      `json:"required_replicas"`
	Acknowledgements []Acknowledgement `json:"acknowledgements"`
	PrepareDeadline  int64             `json:"prepare_deadline"`
	DrainUntil       int64             `json:"drain_until"`
	CommitDeadline   int64             `json:"commit_deadline"`
	UpdatedAt        int64             `json:"updated_at"`
}

type PublishRequest struct {
	ExpectedRevision uint64     `json:"expected_revision"`
	ExpectedActive   Generation `json:"expected_active"`
	Pending          Generation `json:"pending"`
}

type AbortRequest struct {
	ExpectedRevision uint64     `json:"expected_revision"`
	Pending          Generation `json:"pending"`
}

type AckRequest struct {
	ExpectedRevision uint64     `json:"expected_revision"`
	Generation       Generation `json:"generation"`
	Stage            string     `json:"stage"`
}

type ServerConfig struct {
	Store          *Store
	Publisher      Principal
	Replicas       *ReplicaRegistry
	PrepareTimeout time.Duration
	CommitTimeout  time.Duration
	MaxClockSkew   time.Duration
	Logger         *slog.Logger
	Now            func() time.Time
}

type Server struct {
	config   ServerConfig
	mux      *http.ServeMux
	noncesMu sync.Mutex
	nonces   map[string]map[string]time.Time
	stats    coordinatorMetrics
}

type coordinatorMetrics struct {
	stateReads   atomic.Uint64
	publications atomic.Uint64
	aborts       atomic.Uint64
	preparedAcks atomic.Uint64
	activeAcks   atomic.Uint64
	conflicts    atomic.Uint64
	authRejected atomic.Uint64
}

func NewServer(config ServerConfig) (*Server, error) {
	publisherCollides := false
	if config.Replicas != nil {
		_, publisherCollides = config.Replicas.Principal(config.Publisher.ID)
	}
	if config.Store == nil || config.Replicas == nil ||
		!auth.ValidIdentifier(config.Publisher.ID, 64) ||
		config.Publisher.Role != "publisher" || len(config.Publisher.Key) < 32 ||
		len(config.Publisher.Key) > 128 || publisherCollides ||
		!config.Store.RequiredReplicasMatch(config.Replicas.References()) ||
		!config.Replicas.DistinctFrom(config.Publisher.Key, config.Store.key) ||
		keysEqual(config.Publisher.Key, config.Store.key) ||
		config.PrepareTimeout < 30*time.Second || config.PrepareTimeout > 24*time.Hour ||
		config.CommitTimeout < 30*time.Second || config.CommitTimeout > 24*time.Hour ||
		config.MaxClockSkew < 5*time.Second || config.MaxClockSkew > 5*time.Minute {
		return nil, fmt.Errorf("generation coordinator dependencies are invalid")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	server := &Server{config: config, nonces: make(map[string]map[string]time.Time)}
	server.mux = http.NewServeMux()
	server.mux.HandleFunc("GET /healthz", server.health)
	server.mux.HandleFunc("GET /readyz", server.ready)
	server.mux.HandleFunc("GET /metrics", server.metrics)
	server.mux.HandleFunc("GET "+pathState, server.state)
	server.mux.HandleFunc("POST "+pathPublish, server.publish)
	server.mux.HandleFunc("POST "+pathAbort, server.abort)
	server.mux.HandleFunc("POST "+pathAck, server.ack)
	return server, nil
}

func (server *Server) Handler() http.Handler { return server.mux }

func (server *Server) Run(ctxDone <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			if _, err := server.config.Store.Advance(server.config.Now()); err != nil {
				server.config.Logger.Error("generation state advance failed",
					"error_class", "state_advance_failed")
			}
		}
	}
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeAPIJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) ready(writer http.ResponseWriter, _ *http.Request) {
	state, _ := server.config.Store.Snapshot()
	status := http.StatusOK
	value := "ready"
	if state.Phase == PhaseCommitting && server.config.Now().UTC().Unix() > state.CommitDeadline {
		status = http.StatusServiceUnavailable
		value = "convergence_timeout"
	}
	writeAPIJSON(writer, status, map[string]any{
		"status": value, "phase": state.Phase, "revision": state.Revision,
	})
}

func (server *Server) state(writer http.ResponseWriter, request *http.Request) {
	principal, nonce, ok := server.authorize(writer, request, nil)
	if !ok {
		return
	}
	if _, err := server.config.Store.Advance(server.config.Now()); err != nil {
		http.Error(writer, "generation state unavailable", http.StatusServiceUnavailable)
		return
	}
	server.writeSignedState(writer, http.StatusOK, principal, nonce)
	server.stats.stateReads.Add(1)
}

func (server *Server) publish(writer http.ResponseWriter, request *http.Request) {
	var input PublishRequest
	payload, err := readAPIRequest(request)
	if err != nil || decodeCanonicalAPI(payload, &input) != nil {
		http.Error(writer, "invalid generation publication", http.StatusBadRequest)
		return
	}
	principal, nonce, ok := server.authorize(writer, request, payload)
	if !ok {
		return
	}
	if principal.Role != "publisher" {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, err = server.config.Store.Publish(input.ExpectedRevision,
		input.ExpectedActive, input.Pending, server.config.PrepareTimeout,
		server.config.CommitTimeout, server.config.Now())
	if err != nil {
		server.writeMutationError(writer, err)
		return
	}
	server.writeSignedState(writer, http.StatusOK, principal, nonce)
	server.stats.publications.Add(1)
}

func (server *Server) abort(writer http.ResponseWriter, request *http.Request) {
	var input AbortRequest
	payload, err := readAPIRequest(request)
	if err != nil || decodeCanonicalAPI(payload, &input) != nil {
		http.Error(writer, "invalid generation abort", http.StatusBadRequest)
		return
	}
	principal, nonce, ok := server.authorize(writer, request, payload)
	if !ok {
		return
	}
	if principal.Role != "publisher" {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, err = server.config.Store.Abort(input.ExpectedRevision,
		input.Pending, server.config.Now())
	if err != nil {
		server.writeMutationError(writer, err)
		return
	}
	server.writeSignedState(writer, http.StatusOK, principal, nonce)
	server.stats.aborts.Add(1)
}

func (server *Server) ack(writer http.ResponseWriter, request *http.Request) {
	var input AckRequest
	payload, err := readAPIRequest(request)
	if err != nil || decodeCanonicalAPI(payload, &input) != nil {
		http.Error(writer, "invalid generation acknowledgement", http.StatusBadRequest)
		return
	}
	principal, nonce, ok := server.authorize(writer, request, payload)
	if !ok {
		return
	}
	if principal.Role != "controlplane" && principal.Role != "firmwareorigin" {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	_, err = server.config.Store.Acknowledge(input.ExpectedRevision,
		ReplicaRef{ID: principal.ID, Role: principal.Role}, input.Generation,
		input.Stage, server.config.Now())
	if err != nil {
		server.writeMutationError(writer, err)
		return
	}
	server.writeSignedState(writer, http.StatusOK, principal, nonce)
	if input.Stage == AckPrepared {
		server.stats.preparedAcks.Add(1)
	} else {
		server.stats.activeAcks.Add(1)
	}
}

func (server *Server) writeMutationError(writer http.ResponseWriter, err error) {
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrExpired) {
		server.stats.conflicts.Add(1)
		http.Error(writer, "generation state conflict", http.StatusConflict)
		return
	}
	http.Error(writer, "generation state unavailable", http.StatusServiceUnavailable)
}

func (server *Server) authorize(writer http.ResponseWriter, request *http.Request,
	payload []byte) (Principal, string, bool) {
	principalText, principalOK := singleAPIHeader(request, HeaderPrincipal)
	timestampText, timestampOK := singleAPIHeader(request, HeaderTimestamp)
	nonceText, nonceOK := singleAPIHeader(request, HeaderNonce)
	signatureText, signatureOK := singleAPIHeader(request, HeaderSignature)
	if !principalOK || !timestampOK || !nonceOK || !signatureOK ||
		request.URL == nil || request.URL.RawQuery != "" ||
		(request.Method == http.MethodGet &&
			(request.ContentLength != 0 || len(request.TransferEncoding) != 0)) {
		server.stats.authRejected.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return Principal{}, "", false
	}
	principal, found := server.principal(principalText)
	timestamp, timeErr := strconv.ParseInt(timestampText, 10, 64)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(nonceText)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(signatureText)
	now := server.config.Now().UTC()
	if !found || timeErr != nil || strconv.FormatInt(timestamp, 10) != timestampText ||
		nonceErr != nil || len(nonce) != 16 ||
		base64.RawURLEncoding.EncodeToString(nonce) != nonceText ||
		signatureErr != nil || len(signature) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(signature) != signatureText ||
		absDuration(now.Sub(time.Unix(timestamp, 0))) > server.config.MaxClockSkew {
		server.stats.authRejected.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return Principal{}, "", false
	}
	bodyDigest := sha256.Sum256(payload)
	canonical := canonicalAPIRequest(principal.ID, request.Method,
		request.URL.Path, timestampText, nonceText, hex.EncodeToString(bodyDigest[:]))
	mac := hmac.New(sha256.New, principal.Key)
	_, _ = mac.Write([]byte(canonical))
	if subtle.ConstantTimeCompare(signature, mac.Sum(nil)) != 1 ||
		!server.reserveNonce(principal.ID, nonceText, now) {
		server.stats.authRejected.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return Principal{}, "", false
	}
	return principal, nonceText, true
}

func (server *Server) metrics(writer http.ResponseWriter, _ *http.Request) {
	state, _ := server.config.Store.Snapshot()
	timeout := 0
	if state.Phase == PhaseCommitting &&
		server.config.Now().UTC().Unix() > state.CommitDeadline {
		timeout = 1
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(writer,
		"xiaozhi_generation_revision %d\n"+
			"xiaozhi_generation_phase{phase=\"%s\"} 1\n"+
			"xiaozhi_generation_convergence_timeout %d\n"+
			"xiaozhi_generation_state_reads_total %d\n"+
			"xiaozhi_generation_publications_total %d\n"+
			"xiaozhi_generation_aborts_total %d\n"+
			"xiaozhi_generation_prepared_acknowledgements_total %d\n"+
			"xiaozhi_generation_active_acknowledgements_total %d\n"+
			"xiaozhi_generation_conflicts_total %d\n"+
			"xiaozhi_generation_auth_rejected_total %d\n",
		state.Revision, state.Phase, timeout,
		server.stats.stateReads.Load(), server.stats.publications.Load(),
		server.stats.aborts.Load(), server.stats.preparedAcks.Load(),
		server.stats.activeAcks.Load(), server.stats.conflicts.Load(),
		server.stats.authRejected.Load())
}

func (server *Server) principal(id string) (Principal, bool) {
	if id == server.config.Publisher.ID {
		principal := server.config.Publisher
		principal.Key = append([]byte(nil), principal.Key...)
		return principal, true
	}
	return server.config.Replicas.Principal(id)
}

func (server *Server) reserveNonce(principal, nonce string, now time.Time) bool {
	server.noncesMu.Lock()
	defer server.noncesMu.Unlock()
	values := server.nonces[principal]
	if values == nil {
		values = make(map[string]time.Time)
		server.nonces[principal] = values
	}
	for value, expires := range values {
		if !expires.After(now) {
			delete(values, value)
		}
	}
	if _, exists := values[nonce]; exists || len(values) >= 4096 {
		return false
	}
	values[nonce] = now.Add(2 * server.config.MaxClockSkew)
	return true
}

func (server *Server) writeSignedState(writer http.ResponseWriter, status int,
	principal Principal, requestNonce string) {
	state, digest := server.config.Store.Snapshot()
	view := stateView(state, digest)
	payload, err := json.Marshal(view)
	if err != nil {
		http.Error(writer, "generation state unavailable", http.StatusServiceUnavailable)
		return
	}
	payload = append(payload, '\n')
	bodyDigest := sha256.Sum256(payload)
	canonical := canonicalAPIResponse(principal.ID, requestNonce, status,
		hex.EncodeToString(bodyDigest[:]))
	mac := hmac.New(sha256.New, principal.Key)
	_, _ = mac.Write([]byte(canonical))
	writer.Header().Set(HeaderResponseSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}

func stateView(state State, digest string) StateView {
	return StateView{
		Schema: state.Schema, Revision: state.Revision, RecordSHA256: digest,
		Phase: state.Phase, Active: state.Active, Pending: state.Pending,
		RequiredReplicas: append([]ReplicaRef(nil), state.RequiredReplicas...),
		Acknowledgements: append([]Acknowledgement(nil), state.Acknowledgements...),
		PrepareDeadline:  state.PrepareDeadline, DrainUntil: state.DrainUntil,
		CommitDeadline: state.CommitDeadline, UpdatedAt: state.UpdatedAt,
	}
}

func canonicalAPIRequest(principal, method, path, timestamp, nonce,
	bodySHA256 string) string {
	return "xiaozhi-generation-api-v1\n" +
		"principal=" + principal + "\n" +
		"method=" + method + "\n" +
		"path=" + path + "\n" +
		"timestamp=" + timestamp + "\n" +
		"nonce=" + nonce + "\n" +
		"body_sha256=" + bodySHA256 + "\n"
}

func canonicalAPIResponse(principal, nonce string, status int,
	bodySHA256 string) string {
	return "xiaozhi-generation-response-v1\n" +
		"principal=" + principal + "\n" +
		"request_nonce=" + nonce + "\n" +
		"status=" + strconv.Itoa(status) + "\n" +
		"body_sha256=" + bodySHA256 + "\n"
}

func readAPIRequest(request *http.Request) ([]byte, error) {
	if request.Body == nil || request.ContentLength <= 0 ||
		request.ContentLength > maximumAPIBytes ||
		request.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("request body is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumAPIBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumAPIBytes ||
		int64(len(payload)) != request.ContentLength {
		return nil, fmt.Errorf("request body is invalid")
	}
	return payload, nil
}

func decodeCanonicalAPI(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, payload) {
		return fmt.Errorf("API JSON is not canonical")
	}
	return nil
}

func singleAPIHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}

func keysEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func writeAPIJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func randomNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
