package agentproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/usagebudget"
)

type agentTestUsageLedger struct {
	mu              sync.Mutex
	verifyError     error
	reserveError    error
	settleError     error
	uncertainError  error
	reservedSubject string
	inputLimit      int64
	outputLimit     int64
	settledUsage    usagebudget.Usage
	settled         int
	uncertain       int
	released        int
	nextID          byte
}

func (ledger *agentTestUsageLedger) VerifySchema(context.Context) error {
	return ledger.verifyError
}

func (ledger *agentTestUsageLedger) Reserve(_ context.Context, subject string,
	inputLimit, outputLimit int64) (usagebudget.Reservation, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.reserveError != nil {
		return usagebudget.Reservation{}, ledger.reserveError
	}
	ledger.nextID++
	reservation := usagebudget.Reservation{ReservedMicrousd: 100,
		InputTokenLimit: inputLimit, OutputTokenLimit: outputLimit}
	reservation.ID[0] = ledger.nextID
	ledger.reservedSubject = subject
	ledger.inputLimit = inputLimit
	ledger.outputLimit = outputLimit
	return reservation, nil
}

func (ledger *agentTestUsageLedger) Settle(_ context.Context,
	_ usagebudget.Reservation, usage usagebudget.Usage) (usagebudget.Settlement, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.settledUsage = usage
	if ledger.settleError != nil {
		return usagebudget.Settlement{}, ledger.settleError
	}
	ledger.settled++
	return usagebudget.Settlement{CostMicrousd: 7}, nil
}

func (ledger *agentTestUsageLedger) MarkUncertain(context.Context,
	usagebudget.Reservation) (int64, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.uncertainError != nil {
		return 0, ledger.uncertainError
	}
	ledger.uncertain++
	return 100, nil
}

func (ledger *agentTestUsageLedger) Release(context.Context,
	usagebudget.Reservation) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.released++
	return nil
}

func TestProxyReservesAndSettlesVerifiedProviderUsageBeforeDelivery(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":` +
			`{"role":"assistant","content":"ok"}}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer provider.Close()
	ledger := &agentTestUsageLedger{}
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	proxy.config.UsageLedger = ledger
	proxy.config.InputTokenOverhead = 777
	response := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[{"role":"user","content":"hello"}]}`)
	if response.Code != http.StatusOK || ledger.settled != 1 ||
		ledger.uncertain != 0 || ledger.released != 0 ||
		ledger.reservedSubject == "" || ledger.inputLimit <= 777 ||
		ledger.outputLimit != 1024 || ledger.settledUsage.TotalTokens != 7 {
		t.Fatalf("status=%d ledger=%#v body=%s", response.Code, ledger,
			response.Body.String())
	}
	metrics := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_agent_proxy_usage_settled_requests_total 1",
		"xiaozhi_agent_proxy_usage_committed_microusd_total 7",
		"xiaozhi_agent_proxy_usage_uncertain_requests_total 0",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected, metrics.Body.String())
		}
	}
	if strings.Contains(metrics.Body.String(), ledger.reservedSubject) ||
		strings.Contains(metrics.Body.String(), "device-1") {
		t.Fatalf("identity leaked in metrics: %s", metrics.Body.String())
	}
}

func TestProxyMarksContactedRequestUncertainWhenUsageOrSettlementFails(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":` +
			`{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()
	ledger := &agentTestUsageLedger{}
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	proxy.config.UsageLedger = ledger
	response := chatRequest(t, proxy.Handler(), agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[{"role":"user"}]}`)
	if response.Code != http.StatusBadGateway || ledger.uncertain != 1 ||
		ledger.settled != 0 {
		t.Fatalf("missing usage status=%d ledger=%#v", response.Code, ledger)
	}

	settlementProvider := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"choices":[{"message":` +
				`{"role":"assistant","content":"ok"}}],` +
				`"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
		}))
	defer settlementProvider.Close()
	ledger = &agentTestUsageLedger{settleError: usagebudget.ErrUnavailable}
	proxy = testProxy(t, settlementProvider.URL+"/v1/chat/completions", 30)
	proxy.config.UsageLedger = ledger
	response = chatRequest(t, proxy.Handler(), agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[{"role":"user"}]}`)
	if response.Code != http.StatusServiceUnavailable || ledger.uncertain != 1 {
		t.Fatalf("settlement failure status=%d ledger=%#v", response.Code, ledger)
	}
}

func TestProxyRejectsBudgetBeforeProviderAndIncludesLedgerInReadiness(t *testing.T) {
	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		providerCalls++
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer provider.Close()
	ledger := &agentTestUsageLedger{reserveError: usagebudget.ErrBudgetExceeded}
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	proxy.config.UsageLedger = ledger
	response := chatRequest(t, proxy.Handler(), agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[{"role":"user"}]}`)
	if response.Code != http.StatusTooManyRequests || providerCalls != 0 ||
		ledger.uncertain != 0 || ledger.released != 0 {
		t.Fatalf("budget rejection status=%d calls=%d ledger=%#v",
			response.Code, providerCalls, ledger)
	}
	ledger.verifyError = errors.New("schema missing")
	ready := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("usage readiness status=%d", ready.Code)
	}
}

func TestProviderUsageRequiresExactNonnegativeTotals(t *testing.T) {
	valid := []byte(`{"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)
	if usage, ok := providerUsage(valid); !ok || usage.TotalTokens != 7 {
		t.Fatalf("valid usage rejected: %#v ok=%v", usage, ok)
	}
	for _, body := range []string{
		`{}`,
		`{"usage":{"prompt_tokens":5,"completion_tokens":2}}`,
		`{"usage":{"prompt_tokens":5,"completion_tokens":-1,"total_tokens":4}}`,
		`{"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":8}}`,
		`{"usage":{"prompt_tokens":5.5,"completion_tokens":2,"total_tokens":7}}`,
		`{"usage":{"prompt_tokens":5,"prompt_tokens":6,"completion_tokens":2,"total_tokens":8}}`,
	} {
		if _, ok := providerUsage([]byte(body)); ok {
			t.Fatalf("invalid usage accepted: %s", body)
		}
	}
}
