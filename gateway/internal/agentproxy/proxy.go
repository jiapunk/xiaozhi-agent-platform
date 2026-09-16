package agentproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/identityaccess"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
	"xiaozhi-agent-platform/gateway/internal/usagebudget"
)

const maximumDeviceLimiters = 100000

type Config struct {
	Verifier             *auth.Verifier
	Ownership            deviceclaim.OwnershipResolver
	IdentityRegistry     *provisioning.Registry
	AllowInsecure        bool
	ProviderURL          string
	ProviderAPIKey       string
	ProviderModel        string
	ProviderOrganization string
	ProviderProject      string
	PublicModel          string
	HTTPClient           *http.Client
	Logger               *slog.Logger
	MaxOutputTokens      int
	MaxRequestBytes      int64
	MaxResponseBytes     int64
	RequestTimeout       time.Duration
	MaxConcurrent        int
	MaxRequestsMinute    int
	Now                  func() time.Time
	RuntimeCoordinator   runtimecoordination.Coordinator
	UsageLedger          usagebudget.Ledger
	InputTokenOverhead   int64
}

type Proxy struct {
	config      Config
	mux         *http.ServeMux
	concurrency chan struct{}
	limitersMu  sync.Mutex
	limiters    map[string]*deviceLimiter
	stats       metrics
	identity    *identityaccess.Tracker
}

type deviceLimiter struct {
	windowStart time.Time
	requests    int
	inflight    bool
}

type metrics struct {
	requests             atomic.Uint64
	successes            atomic.Uint64
	authFailures         atomic.Uint64
	policyFailures       atomic.Uint64
	rateLimited          atomic.Uint64
	providerErrors       atomic.Uint64
	identityRejected     atomic.Uint64
	identityCanceled     atomic.Uint64
	coordinationFailures atomic.Uint64
	budgetRejected       atomic.Uint64
	usageSettledRequests atomic.Uint64
	usageUncertain       atomic.Uint64
	usageCommittedCost   atomic.Uint64
	usageUncertainCost   atomic.Uint64
	usageFailures        atomic.Uint64
}

type inboundRequest struct {
	Model               string            `json:"model"`
	Messages            []json.RawMessage `json:"messages"`
	Tools               []json.RawMessage `json:"tools,omitempty"`
	MaxTokens           *int              `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int              `json:"max_completion_tokens,omitempty"`
	Stream              *bool             `json:"stream,omitempty"`
}

type providerRequest struct {
	Model               string            `json:"model"`
	Messages            []json.RawMessage `json:"messages"`
	Tools               []json.RawMessage `json:"tools,omitempty"`
	MaxCompletionTokens int               `json:"max_completion_tokens"`
	Store               bool              `json:"store"`
}

func New(config Config) (*Proxy, error) {
	if config.Verifier == nil || config.Ownership == nil ||
		config.ProviderAPIKey == "" ||
		bytes.ContainsAny([]byte(config.ProviderAPIKey), "\r\n") ||
		!validModel(config.ProviderModel) || !validModel(config.PublicModel) ||
		!validOptionalHeaderIdentifier(config.ProviderOrganization) ||
		!validOptionalHeaderIdentifier(config.ProviderProject) ||
		validateProviderURL(config.ProviderURL, config.AllowInsecure) != nil {
		return nil, fmt.Errorf("Agent proxy dependencies are invalid")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 35 * time.Second}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxOutputTokens <= 0 || config.MaxOutputTokens > 8192 {
		config.MaxOutputTokens = 1024
	}
	if config.MaxRequestBytes <= 0 || config.MaxRequestBytes > 1024*1024 {
		config.MaxRequestBytes = 256 * 1024
	}
	if config.MaxResponseBytes <= 0 || config.MaxResponseBytes > 4*1024*1024 {
		config.MaxResponseBytes = 1024 * 1024
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > 2*time.Minute {
		config.RequestTimeout = 35 * time.Second
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 100
	}
	if config.MaxRequestsMinute <= 0 {
		config.MaxRequestsMinute = 30
	}
	if (!config.AllowInsecure && config.UsageLedger == nil) ||
		(config.UsageLedger != nil &&
			(config.InputTokenOverhead < 0 || config.InputTokenOverhead > 65_536)) {
		return nil, fmt.Errorf("Agent usage budget dependencies are invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	proxy := &Proxy{
		config: config, concurrency: make(chan struct{}, config.MaxConcurrent),
		limiters: make(map[string]*deviceLimiter),
	}
	if config.IdentityRegistry != nil {
		identity, err := identityaccess.New(config.IdentityRegistry)
		if err != nil {
			return nil, err
		}
		proxy.identity = identity
	}
	proxy.mux = http.NewServeMux()
	proxy.mux.HandleFunc("GET /healthz", proxy.health)
	proxy.mux.HandleFunc("GET /readyz", proxy.ready)
	proxy.mux.HandleFunc("GET /metrics", proxy.metrics)
	proxy.mux.HandleFunc("POST /v1/chat/completions", proxy.chat)
	return proxy, nil
}

func (proxy *Proxy) Handler() http.Handler { return proxy.mux }

func (proxy *Proxy) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (proxy *Proxy) ready(writer http.ResponseWriter, request *http.Request) {
	if proxy.identity != nil && !proxy.identity.Ready() {
		http.Error(writer, "device identity unavailable", http.StatusServiceUnavailable)
		return
	}
	if proxy.config.RuntimeCoordinator != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		if err := proxy.config.RuntimeCoordinator.VerifySchema(ctx); err != nil {
			http.Error(writer, "runtime coordination unavailable",
				http.StatusServiceUnavailable)
			return
		}
	}
	if proxy.config.UsageLedger != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		if err := proxy.config.UsageLedger.VerifySchema(ctx); err != nil {
			http.Error(writer, "Agent usage budget unavailable",
				http.StatusServiceUnavailable)
			return
		}
	}
	if ownership, ok := proxy.config.Ownership.(deviceclaim.ReadyOwnershipResolver); ok &&
		ownership.VerifySchema() != nil {
		http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (proxy *Proxy) chat(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer)
	proxy.stats.requests.Add(1)
	claims, err := proxy.config.Verifier.VerifyAuthorization(
		request.Header.Get("Authorization"))
	if err != nil {
		proxy.stats.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	ownedScope, ok := auth.OwnedDeviceScope(claims)
	if !ok {
		proxy.stats.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	ownership, owned, ownershipErr := proxy.config.Ownership.Owner(claims.DeviceID)
	if ownershipErr != nil {
		http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
		return
	}
	if !owned || !ownership.Matches(claims.OwnerID, claims.TenantID,
		claims.BindingID, claims.BindingRevision) {
		proxy.stats.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	requestContext := request.Context()
	finishIdentity := func() {}
	if proxy.identity != nil {
		var allowed bool
		controller := http.NewResponseController(writer)
		requestContext, finishIdentity, allowed = proxy.identity.Start(
			request.Context(), claims.DeviceID, func() {
				_ = request.Body.Close()
				_ = controller.SetWriteDeadline(time.Now())
			})
		if !allowed {
			proxy.rejectIdentity(writer)
			return
		}
		defer finishIdentity()
	}
	if request.URL.RawQuery != "" || request.ContentLength == 0 ||
		request.ContentLength > proxy.config.MaxRequestBytes ||
		!jsonContentType(request.Header.Get("Content-Type")) {
		proxy.rejectPolicy(writer, "invalid request size or query")
		return
	}
	requestContext, cancelRequest := context.WithTimeout(requestContext,
		proxy.config.RequestTimeout)
	defer cancelRequest()
	if proxy.config.RuntimeCoordinator != nil {
		lease, coordinationErr := proxy.config.RuntimeCoordinator.AcquireAgent(
			requestContext, ownedScope, proxy.config.MaxRequestsMinute,
			proxy.config.MaxConcurrent, proxy.config.RequestTimeout+15*time.Second)
		if coordinationErr != nil {
			if errors.Is(coordinationErr, runtimecoordination.ErrConflict) ||
				errors.Is(coordinationErr, runtimecoordination.ErrRateLimited) {
				proxy.stats.rateLimited.Add(1)
				writer.Header().Set("Retry-After", "1")
				http.Error(writer, "Agent request rate limited",
					http.StatusTooManyRequests)
				return
			}
			proxy.stats.coordinationFailures.Add(1)
			http.Error(writer, "Agent coordination unavailable",
				http.StatusServiceUnavailable)
			return
		}
		defer proxy.releaseRuntimeLease(lease)
	} else {
		if !proxy.acquireDevice(ownedScope) {
			proxy.stats.rateLimited.Add(1)
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "Agent request rate limited",
				http.StatusTooManyRequests)
			return
		}
		defer proxy.releaseDevice(ownedScope)
		select {
		case proxy.concurrency <- struct{}{}:
			defer func() { <-proxy.concurrency }()
		default:
			proxy.stats.rateLimited.Add(1)
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "Agent proxy busy", http.StatusServiceUnavailable)
			return
		}
	}

	input, err := decodeRequest(io.LimitReader(request.Body,
		proxy.config.MaxRequestBytes+1), proxy.config.PublicModel,
		proxy.config.MaxOutputTokens)
	if err != nil {
		if proxy.identityRevoked(requestContext, claims.DeviceID) {
			proxy.rejectIdentity(writer)
			return
		}
		proxy.rejectPolicy(writer, "invalid Agent request")
		return
	}
	payload, err := json.Marshal(providerRequest{
		Model: proxy.config.ProviderModel, Messages: input.Messages,
		Tools: input.Tools, MaxCompletionTokens: input.outputTokens,
		Store: false,
	})
	if err != nil {
		if proxy.identityRevoked(requestContext, claims.DeviceID) {
			proxy.rejectIdentity(writer)
			return
		}
		proxy.rejectPolicy(writer, "invalid Agent request")
		return
	}
	providerRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost,
		proxy.config.ProviderURL, bytes.NewReader(payload))
	if err != nil {
		proxy.providerFailure(writer, "request_creation")
		return
	}
	providerRequest.Header.Set("Authorization",
		"Bearer "+proxy.config.ProviderAPIKey)
	providerRequest.Header.Set("Content-Type", "application/json")
	providerRequest.Header.Set("Accept", "application/json")
	providerRequest.Header.Set("User-Agent", "xiaozhi-agent-proxy/1")
	if proxy.config.ProviderOrganization != "" {
		providerRequest.Header.Set("OpenAI-Organization",
			proxy.config.ProviderOrganization)
	}
	if proxy.config.ProviderProject != "" {
		providerRequest.Header.Set("OpenAI-Project",
			proxy.config.ProviderProject)
	}
	var reservation usagebudget.Reservation
	finalizedUsage := proxy.config.UsageLedger == nil
	providerContacted := false
	if proxy.config.UsageLedger != nil {
		inputLimit := int64(len(payload)) + proxy.config.InputTokenOverhead
		reservation, err = proxy.config.UsageLedger.Reserve(requestContext,
			ownedScope, inputLimit, int64(input.outputTokens))
		if err != nil {
			if errors.Is(err, usagebudget.ErrBudgetExceeded) {
				proxy.stats.budgetRejected.Add(1)
				writer.Header().Set("Retry-After", "60")
				http.Error(writer, "Agent daily budget exhausted",
					http.StatusTooManyRequests)
				return
			}
			proxy.stats.usageFailures.Add(1)
			http.Error(writer, "Agent usage budget unavailable",
				http.StatusServiceUnavailable)
			return
		}
		defer func() {
			if finalizedUsage {
				return
			}
			if providerContacted {
				proxy.markUsageUncertain(reservation)
				return
			}
			proxy.releaseUsageReservation(reservation)
		}()
	}
	providerContacted = true
	response, err := proxy.config.HTTPClient.Do(providerRequest)
	if err != nil {
		if proxy.identityRevoked(requestContext, claims.DeviceID) {
			proxy.rejectIdentity(writer)
			return
		}
		proxy.providerFailure(writer, "network")
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body,
		proxy.config.MaxResponseBytes+1))
	if proxy.identityRevoked(requestContext, claims.DeviceID) {
		proxy.rejectIdentity(writer)
		return
	}
	if err != nil || int64(len(body)) > proxy.config.MaxResponseBytes ||
		response.StatusCode != http.StatusOK ||
		!jsonContentType(response.Header.Get("Content-Type")) ||
		!validProviderResponse(body) {
		proxy.providerFailure(writer, "invalid_response")
		return
	}
	if proxy.config.UsageLedger != nil {
		usage, valid := providerUsage(body)
		if !valid {
			proxy.providerFailure(writer, "invalid_usage")
			return
		}
		operation, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		settlement, settleErr := proxy.config.UsageLedger.Settle(
			operation, reservation, usage)
		cancel()
		if settleErr != nil {
			proxy.stats.usageFailures.Add(1)
			http.Error(writer, "Agent usage settlement unavailable",
				http.StatusServiceUnavailable)
			return
		}
		finalizedUsage = true
		proxy.stats.usageSettledRequests.Add(1)
		proxy.stats.usageCommittedCost.Add(uint64(settlement.CostMicrousd))
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
	proxy.stats.successes.Add(1)
}

func (proxy *Proxy) markUsageUncertain(reservation usagebudget.Reservation) {
	operation, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cost, err := proxy.config.UsageLedger.MarkUncertain(operation, reservation)
	if err != nil {
		proxy.stats.usageFailures.Add(1)
		return
	}
	proxy.stats.usageUncertain.Add(1)
	proxy.stats.usageUncertainCost.Add(uint64(cost))
}

func (proxy *Proxy) releaseUsageReservation(reservation usagebudget.Reservation) {
	operation, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := proxy.config.UsageLedger.Release(operation, reservation); err != nil {
		proxy.stats.usageFailures.Add(1)
	}
}

func (proxy *Proxy) releaseRuntimeLease(lease runtimecoordination.Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := proxy.config.RuntimeCoordinator.Release(ctx, lease); err != nil &&
		!errors.Is(err, runtimecoordination.ErrLeaseLost) {
		proxy.stats.coordinationFailures.Add(1)
	}
}

func (proxy *Proxy) identityRevoked(ctx context.Context, deviceID string) bool {
	return proxy.identity != nil &&
		(identityaccess.Revoked(ctx) || !proxy.identity.Allowed(deviceID))
}

func (proxy *Proxy) ReconcileIdentity() int {
	if proxy == nil || proxy.identity == nil {
		return 0
	}
	canceled := proxy.identity.Reconcile()
	proxy.stats.identityCanceled.Add(uint64(canceled))
	return canceled
}

type decodedRequest struct {
	Messages     []json.RawMessage
	Tools        []json.RawMessage
	outputTokens int
}

func decodeRequest(reader io.Reader, publicModel string,
	maximumTokens int) (decodedRequest, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var input inboundRequest
	if err := decoder.Decode(&input); err != nil {
		return decodedRequest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return decodedRequest{}, fmt.Errorf("trailing input")
	}
	if input.Model != publicModel || len(input.Messages) == 0 ||
		len(input.Messages) > 64 || len(input.Tools) > 32 ||
		(input.Stream != nil && *input.Stream) ||
		(input.MaxTokens != nil && input.MaxCompletionTokens != nil) {
		return decodedRequest{}, fmt.Errorf("request policy")
	}
	for _, message := range input.Messages {
		if !jsonObject(message) {
			return decodedRequest{}, fmt.Errorf("invalid message")
		}
	}
	for _, tool := range input.Tools {
		if !jsonObject(tool) {
			return decodedRequest{}, fmt.Errorf("invalid tool")
		}
	}
	requested := maximumTokens
	if input.MaxCompletionTokens != nil {
		requested = *input.MaxCompletionTokens
	} else if input.MaxTokens != nil {
		requested = *input.MaxTokens
	}
	if requested <= 0 || requested > maximumTokens {
		return decodedRequest{}, fmt.Errorf("output token policy")
	}
	return decodedRequest{
		Messages: input.Messages, Tools: input.Tools,
		outputTokens: requested,
	}, nil
}

func jsonObject(value json.RawMessage) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(value, &object) == nil && object != nil
}

func validProviderResponse(body []byte) bool {
	var response struct {
		Choices []struct {
			Message struct {
				Role      string            `json:"role"`
				Content   *string           `json:"content"`
				ToolCalls []json.RawMessage `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Choices) == 0 ||
		len(response.Choices) > 8 || response.Choices[0].Message.Role != "assistant" {
		return false
	}
	message := response.Choices[0].Message
	if (message.Content == nil || *message.Content == "") &&
		len(message.ToolCalls) == 0 {
		return false
	}
	if message.Content != nil && len(*message.Content) > 64*1024 {
		return false
	}
	if len(message.ToolCalls) > 32 {
		return false
	}
	for _, toolCall := range message.ToolCalls {
		if !jsonObject(toolCall) {
			return false
		}
	}
	return true
}

func providerUsage(body []byte) (usagebudget.Usage, bool) {
	var response struct {
		Usage *struct {
			PromptTokens     *int64 `json:"prompt_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
			TotalTokens      *int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if strictjson.RejectDuplicateFields(body) != nil ||
		json.Unmarshal(body, &response) != nil || response.Usage == nil ||
		response.Usage.PromptTokens == nil ||
		response.Usage.CompletionTokens == nil ||
		response.Usage.TotalTokens == nil {
		return usagebudget.Usage{}, false
	}
	usage := usagebudget.Usage{
		InputTokens:  *response.Usage.PromptTokens,
		OutputTokens: *response.Usage.CompletionTokens,
		TotalTokens:  *response.Usage.TotalTokens,
	}
	return usage, usage.Validate() == nil
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func (proxy *Proxy) acquireDevice(ownedScope string) bool {
	proxy.limitersMu.Lock()
	defer proxy.limitersMu.Unlock()
	limiter := proxy.limiters[ownedScope]
	if limiter == nil {
		if len(proxy.limiters) >= maximumDeviceLimiters {
			return false
		}
		limiter = &deviceLimiter{}
		proxy.limiters[ownedScope] = limiter
	}
	now := proxy.config.Now().UTC()
	if limiter.windowStart.IsZero() || now.Sub(limiter.windowStart) >= time.Minute {
		limiter.windowStart = now
		limiter.requests = 0
	}
	if limiter.inflight || limiter.requests >= proxy.config.MaxRequestsMinute {
		return false
	}
	limiter.inflight = true
	limiter.requests++
	return true
}

func (proxy *Proxy) releaseDevice(ownedScope string) {
	proxy.limitersMu.Lock()
	if limiter := proxy.limiters[ownedScope]; limiter != nil {
		limiter.inflight = false
	}
	proxy.limitersMu.Unlock()
}

func (proxy *Proxy) rejectPolicy(writer http.ResponseWriter, detail string) {
	proxy.stats.policyFailures.Add(1)
	proxy.config.Logger.Info("Agent request rejected",
		"error_class", "policy_rejected", "detail", detail)
	http.Error(writer, "invalid Agent request", http.StatusBadRequest)
}

func (proxy *Proxy) providerFailure(writer http.ResponseWriter,
	errorClass string) {
	proxy.stats.providerErrors.Add(1)
	proxy.config.Logger.Info("Agent provider request failed",
		"error_class", errorClass)
	http.Error(writer, "Agent provider unavailable", http.StatusBadGateway)
}

func (proxy *Proxy) rejectIdentity(writer http.ResponseWriter) {
	proxy.stats.identityRejected.Add(1)
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func (proxy *Proxy) metrics(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(writer,
		"xiaozhi_agent_proxy_requests_total %d\n"+
			"xiaozhi_agent_proxy_successes_total %d\n"+
			"xiaozhi_agent_proxy_auth_failures_total %d\n"+
			"xiaozhi_agent_proxy_policy_failures_total %d\n"+
			"xiaozhi_agent_proxy_rate_limited_total %d\n"+
			"xiaozhi_agent_proxy_provider_errors_total %d\n"+
			"xiaozhi_agent_proxy_identity_rejected_total %d\n"+
			"xiaozhi_agent_proxy_identity_canceled_total %d\n"+
			"xiaozhi_agent_proxy_coordination_failures_total %d\n"+
			"xiaozhi_agent_proxy_budget_rejected_total %d\n"+
			"xiaozhi_agent_proxy_usage_settled_requests_total %d\n"+
			"xiaozhi_agent_proxy_usage_uncertain_requests_total %d\n"+
			"xiaozhi_agent_proxy_usage_committed_microusd_total %d\n"+
			"xiaozhi_agent_proxy_usage_uncertain_microusd_total %d\n"+
			"xiaozhi_agent_proxy_usage_failures_total %d\n",
		proxy.stats.requests.Load(), proxy.stats.successes.Load(),
		proxy.stats.authFailures.Load(), proxy.stats.policyFailures.Load(),
		proxy.stats.rateLimited.Load(), proxy.stats.providerErrors.Load(),
		proxy.stats.identityRejected.Load(), proxy.stats.identityCanceled.Load(),
		proxy.stats.coordinationFailures.Load(), proxy.stats.budgetRejected.Load(),
		proxy.stats.usageSettledRequests.Load(), proxy.stats.usageUncertain.Load(),
		proxy.stats.usageCommittedCost.Load(), proxy.stats.usageUncertainCost.Load(),
		proxy.stats.usageFailures.Load())
}

func setSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
