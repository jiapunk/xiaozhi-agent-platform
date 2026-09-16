package mtlsdispatchqualification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
	"xiaozhi-agent-platform/gateway/internal/appdeliveryqualification"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

type acceptedWakeSender struct{ calls int }

func (sender *acceptedWakeSender) SendWake(_ context.Context,
	_ actionconsent.Actor, contract string, payload []byte) (
	actionconsent.WakeSendDisposition, error) {
	if contract != actionconsent.WakeContract ||
		string(payload) != string(actionconsent.CanonicalWakePayload()) {
		return actionconsent.WakeSendRetry, pushdelivery.ErrInvalid
	}
	sender.calls++
	return actionconsent.WakeSendAccepted, nil
}

type certificateAuthority struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	pem         []byte
}

func TestRunnerUsesProductionPathAndRejectsInvalidTLSIdentities(t *testing.T) {
	trusted := newCertificateAuthority(t, "trusted-workload-root")
	revoked := newCertificateAuthority(t, "revoked-workload-root")
	serverCertificatePEM, serverKeyPEM, serverDER := issueCertificate(t,
		trusted, "accountauthorization", false, true)
	currentPEM, currentKey, currentDER := issueCertificate(t,
		trusted, "controlplane-current", true, false)
	nextPEM, nextKey, nextDER := issueCertificate(t,
		trusted, "controlplane-next", true, false)
	revokedPEM, revokedKey, revokedDER := issueCertificate(t,
		revoked, "controlplane-revoked", true, false)

	sender := &acceptedWakeSender{}
	handler, err := pushdelivery.NewPrivateWakeHandler(sender)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	serverTLS, err := accountauth.NewIntrospectionMTLSServerConfig(
		trusted.pem, serverCertificatePEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.MinVersion = tls.VersionTLS13
	server.TLS = serverTLS
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	parsed, _ := url.Parse(server.URL)

	currentClient, currentTLS := testClient(t, trusted.pem, currentPEM,
		currentKey, parsed.Hostname())
	nextClient, _ := testClient(t, trusted.pem, nextPEM,
		nextKey, parsed.Hostname())
	_, revokedTLS := testClient(t, trusted.pem, revokedPEM,
		revokedKey, parsed.Hostname())
	anonymousTLS := currentTLS.Clone()
	anonymousTLS.Certificates = nil
	wrongNameTLS := currentTLS.Clone()
	wrongNameTLS.ServerName = "wrong.invalid"
	config := RunConfig{
		QualificationID: "m71-runner-1", Environment: "staging",
		DevelopmentOnly: true, DeploymentID: "m71-pilot",
		OCIReleaseID: "oci-release-1", Services: append([]string(nil), ExactServices...),
		Authority: server.URL, NetworkAddress: parsed.Host,
		EndpointAuthoritySHA256:           strings.Repeat("0", 64),
		ConfigSHA256:                      strings.Repeat("1", 64),
		ToolSHA256:                        strings.Repeat("2", 64),
		KubernetesDeploymentReceiptSHA256: strings.Repeat("3", 64),
		KubernetesAdmissionReceiptSHA256:  strings.Repeat("4", 64),
		ControlplanePodBindingSHA256:      strings.Repeat("5", 64),
		CurrentClientCertificateSHA256:    digestDER(currentDER),
		NextClientCertificateSHA256:       digestDER(nextDER),
		RevokedClientCertificateSHA256:    digestDER(revokedDER),
		ExpectedServerLeafSHA256:          digestDER(serverDER),
		CurrentClient:                     currentClient, NextClient: nextClient,
		AnonymousTLS: anonymousTLS, RevokedTLS: revokedTLS,
		WrongServerNameTLS: wrongNameTLS,
		Actor: actionconsent.Actor{TenantID: "tenant-1", OwnerID: "user-1",
			DeviceID: "device-1", OwnerRevision: 42},
	}
	observation, err := NewRunner().Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if observation.NegotiatedProtocol != HTTP2Protocol ||
		observation.TLSVersion != TLSVersion13 || sender.calls != 3 ||
		observation.ServerLeafCertificateSHA256 != digestDER(serverDER) {
		t.Fatalf("observation=%+v calls=%d", observation, sender.calls)
	}
	payload, err := CanonicalObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseObservation(payload); err != nil {
		t.Fatal(err)
	}

	invalid := config
	invalid.RevokedTLS = currentTLS.Clone()
	if _, err := NewRunner().Run(context.Background(), invalid); err == nil {
		t.Fatal("a trusted certificate was misclassified as revoked")
	}
}

func TestObservationRejectsAmbiguousAndOverstatedEvidence(t *testing.T) {
	observation := fixtureDispatchObservation(time.Date(
		2026, 8, 10, 12, 0, 0, 0, time.UTC))
	payload, _ := CanonicalObservation(observation)
	duplicate := strings.Replace(string(payload), `"schema":1`,
		`"schema":1,"schema":1`, 1)
	if _, err := ParseObservation([]byte(duplicate)); err == nil {
		t.Fatal("duplicate observation field accepted")
	}
	observation.NegotiatedProtocol = "http/1.1"
	payload, _ = CanonicalObservation(observation)
	if _, err := ParseObservation(payload); err == nil {
		t.Fatal("non-HTTP/2 dispatch evidence accepted")
	}
}

func TestClientCertificatePEMChainIsExact(t *testing.T) {
	authority := newCertificateAuthority(t, "chain-root")
	leafPEM, _, leafDER := issueCertificate(t, authority,
		"chain-client", true, false)
	chain := append(append([]byte(nil), leafPEM...), authority.pem...)
	if !certificatePEMMatchesChain(chain,
		[][]byte{leafDER, authority.certificate.Raw}) {
		t.Fatal("valid client certificate chain rejected")
	}
	if certificatePEMMatchesChain(append(chain, []byte("junk")...),
		[][]byte{leafDER, authority.certificate.Raw}) {
		t.Fatal("trailing client certificate material accepted")
	}
}

func TestLiveConfigRequiresExactServiceEndpointAndAbsolutePaths(t *testing.T) {
	document := liveConfigDocument{Schema: 1,
		QualificationID: "m71-config-1", Environment: "staging",
		AcknowledgeLiveDispatch: true, DeploymentID: "m71-pilot",
		OCIReleaseID: "oci-release-1", Services: append([]string(nil), ExactServices...),
		Endpoint: "https://m71-pilot-accountauthorization:9444",
		ServerCAFile: "relative-ca.pem",
		ExpectedServerLeafCertificateSHA256: strings.Repeat("a", 64),
		CurrentClientCertificateFile: "current.pem", CurrentClientKeyFile: "current.key",
		NextClientCertificateFile: "next.pem", NextClientKeyFile: "next.key",
		RevokedClientCertificateFile: "revoked.pem", RevokedClientKeyFile: "revoked.key",
		KubernetesDeploymentReceiptFile: "deployment.json",
		KubernetesAdmissionReceiptFile: "admission.json",
		ControlplanePodUIDFile: "pod-uid", QualificationNonce: "AAAAAAAAAAAAAAAAAAAAAA",
		TenantID: "tenant-1", Subject: "user-1", DeviceID: "device-1",
		OwnerRevision: 1}
	path := filepath.Join(t.TempDir(), "config.json")
	writeTestFile(t, path, canonicalJSON(t, document), 0o600)
	if _, err := LoadLiveConfig(path, time.Second); err == nil {
		t.Fatal("relative live qualification paths were accepted")
	}
	document.ServerCAFile = "/run/qualification/ca.pem"
	document.CurrentClientCertificateFile = "/run/qualification/current.pem"
	document.CurrentClientKeyFile = "/run/qualification/current.key"
	document.NextClientCertificateFile = "/run/qualification/next.pem"
	document.NextClientKeyFile = "/run/qualification/next.key"
	document.RevokedClientCertificateFile = "/run/qualification/revoked.pem"
	document.RevokedClientKeyFile = "/run/qualification/revoked.key"
	document.KubernetesDeploymentReceiptFile = "/run/qualification/deployment.json"
	document.KubernetesAdmissionReceiptFile = "/run/qualification/admission.json"
	document.ControlplanePodUIDFile = "/run/qualification/pod-uid"
	document.Endpoint = "https://other-accountauthorization:9444"
	path = filepath.Join(t.TempDir(), "wrong-endpoint.json")
	writeTestFile(t, path, canonicalJSON(t, document), 0o600)
	if _, err := LoadLiveConfig(path, time.Second); err == nil {
		t.Fatal("cross-deployment qualification endpoint was accepted")
	}
}

func TestFixtureReceiptChainCannotSatisfyLiveVerifier(t *testing.T) {
	directory := t.TempDir()
	providerPrivate, providerPublic := writeEd25519Pair(t, directory, "provider")
	appAttestationPrivate, appAttestationPublic := writeEd25519Pair(
		t, directory, "app-attestation")
	appFinalPrivate, appFinalPublic := writeEd25519Pair(t, directory, "app-final")
	deploymentPrivate, deploymentPublic := writeEd25519Pair(
		t, directory, "deployment")
	finalPrivate, finalPublic := writeEd25519Pair(t, directory, "final")

	provider := pushqualification.Receipt{Schema: 1,
		QualificationID: "m71-fixture-1",
		Result:          pushqualification.FixtureResult, Environment: "staging",
		ConfigSHA256:            strings.Repeat("0", 64),
		QualificationToolSHA256: strings.Repeat("1", 64),
		StartedAt:               "2026-08-10T12:00:00Z", FinishedAt: "2026-08-10T12:00:01Z",
		DevelopmentOnly: true, SecretFree: true,
		Providers: []pushqualification.ProviderEvidence{{
			Platform:            accountauth.PushPlatformAPNSDevelopment,
			ApplicationID:       "com.example.product",
			CurrentCredentialID: "fixture-current-1",
			NextCredentialID:    "fixture-next-2",
			CurrentAccepted:     true, NextAccepted: true,
			InvalidTargetClassified: true, CanceledRequestRetried: true,
			CurrentLatencyMS: 10, NextLatencyMS: 11,
			InvalidClassificationMS: 12}},
		ProductionReady: false,
		UnresolvedProductionGates: []string{"end_to_end_mtls_dispatch",
			"managed_database_failover", "provider_credential_revocation",
			"signed_app_delivery_receipt"}}
	providerPayload, err := pushqualification.SignReceipt(
		provider, providerPrivate, "provider-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(directory, "provider.json")
	writeTestFile(t, providerPath, providerPayload, 0o444)

	appWake := time.Date(2026, 8, 10, 12, 0, 0, 200_000_000, time.UTC)
	appObservation := appdeliveryqualification.Observation{Schema: 1,
		QualificationID:    "m71-fixture-1",
		QualificationNonce: "AAAAAAAAAAAAAAAAAAAAAA",
		Environment:        "staging", DevelopmentOnly: true, Platform: "ios",
		ApplicationID: "com.example.product", AppBuildID: "ios-fixture-1",
		AppBinarySHA256: strings.Repeat("a", 64),
		WakeContract:    appdeliveryqualification.WakeContract,
		ContentFreeWake: true, BackgroundNetworkRequest: false,
		BackgroundWakeCount:       1,
		WakeReceivedAtUnixMS:      uint64(appWake.UnixMilli()),
		ForegroundEnteredAtUnixMS: uint64(appWake.Add(time.Second).UnixMilli()),
		AuthenticatedFetchPresentedAtUnixMS: uint64(
			appWake.Add(1200 * time.Millisecond).UnixMilli()),
		WakeToFetchMS:          1200,
		ChallengeBindingSHA256: strings.Repeat("b", 64),
		DeviceBindingSHA256:    strings.Repeat("c", 64), DecisionIssued: false}
	appObservationPayload := canonicalJSON(t, appObservation)
	appObservationPath := filepath.Join(directory, "app-observation.json")
	writeTestFile(t, appObservationPath, appObservationPayload, 0o444)
	appVerifiedAt := time.Date(2026, 8, 10, 12, 0, 2, 0, time.UTC)
	appAttestationPayload, err := appdeliveryqualification.SignAttestation(
		appdeliveryqualification.AttestationInput{Observation: appObservation,
			ObservationSHA256:                  digest(appObservationPayload),
			ProviderQualificationReceiptSHA256: digest(providerPayload),
			VendorEvidenceSHA256:               strings.Repeat("d", 64),
			AttestedKeySHA256:                  strings.Repeat("e", 64),
			Provider:                           appdeliveryqualification.FixtureAttestationProvider,
			VerifiedAt:                         appVerifiedAt, ExpiresAt: appVerifiedAt.Add(time.Hour),
			DevelopmentOnly: true}, appAttestationPrivate,
		"app-attestation-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	appAttestationPath := filepath.Join(directory, "app-attestation.json")
	writeTestFile(t, appAttestationPath, appAttestationPayload, 0o444)
	appEvidence := appdeliveryqualification.EvidenceOptions{
		ObservationPath:     appObservationPath,
		ProviderReceiptPath: providerPath,
		ProviderVerifyOptions: pushqualification.VerifyOptions{
			TrustedPublicKey:        providerPublic,
			ExpectedSigningKeyID:    "provider-fixture-key",
			ExpectedQualificationID: "m71-fixture-1",
			ExpectedEnvironment:     "staging",
			ExpectedConfigSHA256:    strings.Repeat("0", 64),
			ExpectedToolSHA256:      strings.Repeat("1", 64)},
		AttestationReceiptPath: appAttestationPath,
		AttestationVerifyOptions: appdeliveryqualification.AttestationVerifyOptions{
			TrustedPublicKey:     appAttestationPublic,
			ExpectedSigningKeyID: "app-attestation-fixture-key",
			ExpectedProvider:     appdeliveryqualification.FixtureAttestationProvider,
			ExpectedVendorSHA256: strings.Repeat("d", 64)},
		EvaluationTime: appVerifiedAt}
	appReceipt, err := appdeliveryqualification.BuildReceipt(appEvidence)
	if err != nil {
		t.Fatal(err)
	}
	appReceiptPayload, err := appdeliveryqualification.SignReceipt(
		appReceipt, appFinalPrivate, "app-final-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	appReceiptPath := filepath.Join(directory, "app-delivery.json")
	writeTestFile(t, appReceiptPath, appReceiptPayload, 0o444)

	dispatchObservation := fixtureDispatchObservation(time.Date(
		2026, 8, 10, 12, 0, 0, 0, time.UTC))
	dispatchObservationPayload, _ := CanonicalObservation(dispatchObservation)
	dispatchObservationPath := filepath.Join(directory, "dispatch-observation.json")
	writeTestFile(t, dispatchObservationPath, dispatchObservationPayload, 0o444)
	deploymentVerifiedAt := time.Date(2026, 8, 10, 12, 0, 3, 0, time.UTC)
	deploymentAttestationPayload, err := SignAttestation(AttestationInput{
		Observation:            dispatchObservation,
		ObservationSHA256:      digest(dispatchObservationPayload),
		WorkloadEvidenceSHA256: strings.Repeat("f", 64),
		Provider:               FixtureAttestationProvider,
		VerifiedAt:             deploymentVerifiedAt,
		ExpiresAt:              deploymentVerifiedAt.Add(time.Hour),
		DevelopmentOnly:        true}, deploymentPrivate,
		"deployment-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	deploymentAttestationPath := filepath.Join(directory, "deployment-attestation.json")
	writeTestFile(t, deploymentAttestationPath,
		deploymentAttestationPayload, 0o444)
	evaluatedAt := time.Date(2026, 8, 10, 12, 0, 4, 0, time.UTC)
	evidence := EvidenceOptions{
		ObservationPath:        dispatchObservationPath,
		AppDeliveryReceiptPath: appReceiptPath,
		AppDeliveryVerifyOptions: appdeliveryqualification.ReceiptVerifyOptions{
			TrustedPublicKey:                 appFinalPublic,
			ExpectedSigningKeyID:             "app-final-fixture-key",
			ExpectedQualificationID:          "m71-fixture-1",
			ExpectedEnvironment:              "staging",
			ExpectedAppBinarySHA256:          strings.Repeat("a", 64),
			ExpectedProviderReceiptSHA256:    digest(providerPayload),
			ExpectedObservationSHA256:        digest(appObservationPayload),
			ExpectedAttestationReceiptSHA256: digest(appAttestationPayload),
			ExpectedEvaluationTime:           appVerifiedAt.Format(time.RFC3339)},
		AppDeliveryEvidenceOptions:       appEvidence,
		DeploymentAttestationReceiptPath: deploymentAttestationPath,
		DeploymentAttestationVerifyOptions: AttestationVerifyOptions{
			TrustedPublicKey:               deploymentPublic,
			ExpectedSigningKeyID:           "deployment-fixture-key",
			ExpectedProvider:               FixtureAttestationProvider,
			ExpectedWorkloadEvidenceSHA256: strings.Repeat("f", 64)},
		EvaluationTime: evaluatedAt}
	receipt, err := BuildReceipt(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result != FixtureResult || !receipt.DevelopmentOnly ||
		receipt.ExactSevenServiceDeploymentVerified ||
		len(receipt.UnresolvedProductionGates) != 4 ||
		receipt.UnresolvedProductionGates[0] != "end_to_end_mtls_dispatch" {
		t.Fatalf("receipt=%+v", receipt)
	}
	receiptPayload, err := SignReceipt(receipt, finalPrivate, "m71-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyReceipt(receiptPayload, ReceiptVerifyOptions{
		TrustedPublicKey:        finalPublic,
		ExpectedSigningKeyID:    "m71-fixture-key",
		ExpectedQualificationID: "m71-fixture-1",
		ExpectedEnvironment:     "staging", ExpectedDeploymentID: "m71-pilot",
		ExpectedOCIReleaseID:                "oci-release-1",
		ExpectedObservationSHA256:           digest(dispatchObservationPayload),
		ExpectedAppDeliveryReceiptSHA256:    digest(appReceiptPayload),
		ExpectedDeploymentAttestationSHA256: digest(deploymentAttestationPayload),
		ExpectedEvaluationTime:              evaluatedAt.Format(time.RFC3339)})
	if err != nil || !ReceiptMatchesEvidence(verified, receipt) {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if _, err := VerifyReceipt(receiptPayload, ReceiptVerifyOptions{
		TrustedPublicKey: finalPublic, RequireLive: true}); err == nil {
		t.Fatal("fixture receipt satisfied live verifier")
	}
	liveEvidence := evidence
	liveEvidence.RequireLive = true
	if _, err := BuildReceipt(liveEvidence); err == nil {
		t.Fatal("fixture evidence built a live receipt")
	}
	staleEvidence := evidence
	staleEvidence.EvaluationTime = appVerifiedAt.Add(11 * time.Minute)
	if _, err := BuildReceipt(staleEvidence); err == nil {
		t.Fatal("stale cross-system evidence was accepted")
	}
}

func fixtureDispatchObservation(started time.Time) Observation {
	return Observation{Schema: ObservationSchema,
		QualificationID: "m71-fixture-1", Environment: "staging",
		DevelopmentOnly: true, DeploymentID: "m71-pilot",
		OCIReleaseID: "oci-release-1", Services: append([]string(nil), ExactServices...),
		EndpointAuthoritySHA256:           strings.Repeat("0", 64),
		ConfigSHA256:                      strings.Repeat("1", 64),
		QualificationToolSHA256:           strings.Repeat("2", 64),
		KubernetesDeploymentReceiptSHA256: strings.Repeat("3", 64),
		KubernetesAdmissionReceiptSHA256:  strings.Repeat("4", 64),
		ControlplanePodBindingSHA256:      strings.Repeat("5", 64),
		CurrentClientCertificateSHA256:    strings.Repeat("6", 64),
		NextClientCertificateSHA256:       strings.Repeat("7", 64),
		RevokedClientCertificateSHA256:    strings.Repeat("8", 64),
		ServerLeafCertificateSHA256:       strings.Repeat("9", 64),
		TLSVersion:                        TLSVersion13, NegotiatedProtocol: HTTP2Protocol,
		WakeContract:              pushdelivery.PrivateWakeContract,
		CurrentCredentialAccepted: true, NextCredentialAccepted: true,
		AnonymousClientRejected: true, RevokedClientRejected: true,
		WrongServerNameRejected: true, CurrentLatencyMS: 10, NextLatencyMS: 11,
		StartedAt:  started.Format(time.RFC3339),
		FinishedAt: started.Add(time.Second).Format(time.RFC3339), SecretFree: true}
}

func newCertificateAuthority(t *testing.T, commonName string) certificateAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template,
		publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificateAuthority{certificate: certificate, privateKey: privateKey,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func issueCertificate(t *testing.T, authority certificateAuthority,
	commonName string, client, server bool) ([]byte, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	usage := []x509.ExtKeyUsage{}
	if client {
		usage = append(usage, x509.ExtKeyUsageClientAuth)
	}
	if server {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := &x509.Certificate{SerialNumber: serial,
		Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usage}
	if server {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template,
		authority.certificate, publicKey, authority.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), der
}

func testClient(t *testing.T, caPEM, certificatePEM, keyPEM []byte,
	serverName string) (*http.Client, *tls.Config) {
	t.Helper()
	client, err := auth.NewCompanionIntrospectionMTLSClient(
		caPEM, certificatePEM, keyPEM, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA rejected")
	}
	return client, &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{certificate},
		ServerName: serverName, NextProtos: []string{HTTP2Protocol}}
}

func digestDER(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// Keep fixture helpers used by later receipt-chain tests in this package.
func writeTestFile(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
}

func writeEd25519Pair(t *testing.T, directory, name string) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	privatePath := filepath.Join(directory, name+"-private.pem")
	publicPath := filepath.Join(directory, name+"-public.pem")
	writeTestFile(t, privatePath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	writeTestFile(t, publicPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	return privatePath, publicPath
}

func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(payload, '\n')
}
