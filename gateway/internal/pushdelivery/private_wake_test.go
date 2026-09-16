package pushdelivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/actionconsent"
)

type wakeSenderStub struct {
	disposition actionconsent.WakeSendDisposition
	err         error
	actor       actionconsent.Actor
	contract    string
	payload     []byte
}

func (stub *wakeSenderStub) SendWake(_ context.Context,
	actor actionconsent.Actor, contract string, payload []byte) (
	actionconsent.WakeSendDisposition, error) {
	stub.actor = actor
	stub.contract = contract
	stub.payload = append([]byte(nil), payload...)
	return stub.disposition, stub.err
}

func privateWakeRequestFixture(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost,
		"https://accountauthorization.internal"+PrivateWakePath,
		strings.NewReader(body))
	certificate := &x509.Certificate{}
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}}}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Private-Wake", PrivateWakeContract)
	return request
}

func TestPrivateWakeHandlerForwardsOnlyCanonicalWake(t *testing.T) {
	sender := &wakeSenderStub{disposition: actionconsent.WakeSendAccepted}
	handler, _ := NewPrivateWakeHandler(sender)
	body := `{"version":1,"tenant_id":"tenant-1","subject":"user-1","device_id":"device-1","owner_revision":42}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, privateWakeRequestFixture(body))
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("X-Xiaozhi-Wake-Disposition") != "accepted" ||
		sender.actor.OwnerID != "user-1" || sender.actor.TenantID != "tenant-1" ||
		sender.actor.DeviceID != "device-1" || sender.actor.OwnerRevision != 42 ||
		sender.contract != actionconsent.WakeContract ||
		!bytes.Equal(sender.payload, actionconsent.CanonicalWakePayload()) {
		t.Fatalf("response=%#v sender=%#v", response.Result(), sender)
	}
}

func TestPrivateWakeHandlerRejectsNonMTLSAndNoncanonicalBodies(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.TLS.VerifiedChains = nil },
		func(request *http.Request) { request.Header.Add("Content-Type", "application/json") },
		func(request *http.Request) { request.URL.RawQuery = "x=1" },
	} {
		sender := &wakeSenderStub{disposition: actionconsent.WakeSendAccepted}
		handler, _ := NewPrivateWakeHandler(sender)
		request := privateWakeRequestFixture(
			`{"version":1,"tenant_id":"tenant-1","subject":"user-1","device_id":"device-1","owner_revision":42}`)
		mutate(request)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || sender.actor != (actionconsent.Actor{}) {
			t.Fatalf("status=%d actor=%#v", response.Code, sender.actor)
		}
	}
	sender := &wakeSenderStub{disposition: actionconsent.WakeSendAccepted}
	handler, _ := NewPrivateWakeHandler(sender)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, privateWakeRequestFixture(
		`{"version":1,"tenant_id":"tenant-1","subject":"user-1","device_id":"device-1","owner_revision":42}`+"\n"))
	if response.Code != http.StatusBadRequest || sender.actor != (actionconsent.Actor{}) {
		t.Fatal("noncanonical body reached sender")
	}
}

func TestMTLSWakeClientUsesExactPrivateContract(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != PrivateWakePath ||
			request.Header.Get("X-Xiaozhi-Private-Wake") != PrivateWakeContract ||
			string(body) != `{"version":1,"tenant_id":"tenant-1","subject":"user-1","device_id":"device-1","owner_revision":42}` {
			t.Errorf("unexpected private wake request: %s %s %q",
				request.Method, request.URL.Path, body)
		}
		setPrivateWakeHeaders(writer.Header())
		writer.Header().Set("X-Xiaozhi-Wake-Disposition", "accepted")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	httpClient := trustedTestClient(server, true)
	client, err := NewMTLSWakeClient(server.URL, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := client.SendWake(context.Background(), actionconsent.Actor{
		OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-1",
		OwnerRevision: 42,
	}, actionconsent.WakeContract, actionconsent.CanonicalWakePayload())
	if err != nil || disposition != actionconsent.WakeSendAccepted {
		t.Fatalf("disposition=%d err=%v", disposition, err)
	}
}

func TestMTLSWakeClientDoesNotSurfacePrivateErrorBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		setPrivateWakeHeaders(writer.Header())
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte("provider-secret-diagnostic"))
	}))
	defer server.Close()
	httpClient := trustedTestClient(server, true)
	httpClient.Timeout = time.Second
	client, _ := NewMTLSWakeClient(server.URL, httpClient)
	_, err := client.SendWake(context.Background(), actionconsent.Actor{
		OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-1",
		OwnerRevision: 42,
	}, actionconsent.WakeContract, actionconsent.CanonicalWakePayload())
	if err == nil || strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("private diagnostic escaped: %v", err)
	}
}
