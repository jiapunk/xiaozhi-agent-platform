package mtlsdispatchqualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	maximumConfigBytes = int64(64 * 1024)
	podBindingDomain   = "XIAOZHI-M71-CONTROLPLANE-POD-BINDING-V1\x00"
	endpointDomain     = "XIAOZHI-M71-ENDPOINT-AUTHORITY-V1\x00"
)

type liveConfigDocument struct {
	Schema                              uint32   `json:"schema"`
	QualificationID                     string   `json:"qualification_id"`
	Environment                         string   `json:"environment"`
	AcknowledgeLiveDispatch             bool     `json:"acknowledge_live_dispatch"`
	DeploymentID                        string   `json:"deployment_id"`
	OCIReleaseID                        string   `json:"oci_release_id"`
	Services                            []string `json:"services"`
	Endpoint                            string   `json:"endpoint"`
	ServerCAFile                        string   `json:"server_ca_file"`
	ExpectedServerLeafCertificateSHA256 string   `json:"expected_server_leaf_certificate_sha256"`
	CurrentClientCertificateFile        string   `json:"current_client_certificate_file"`
	CurrentClientKeyFile                string   `json:"current_client_key_file"`
	NextClientCertificateFile           string   `json:"next_client_certificate_file"`
	NextClientKeyFile                   string   `json:"next_client_key_file"`
	RevokedClientCertificateFile        string   `json:"revoked_client_certificate_file"`
	RevokedClientKeyFile                string   `json:"revoked_client_key_file"`
	KubernetesDeploymentReceiptFile     string   `json:"kubernetes_deployment_receipt_file"`
	KubernetesAdmissionReceiptFile      string   `json:"kubernetes_admission_receipt_file"`
	ControlplanePodUIDFile              string   `json:"controlplane_pod_uid_file"`
	QualificationNonce                  string   `json:"qualification_nonce"`
	TenantID                            string   `json:"tenant_id"`
	Subject                             string   `json:"subject"`
	DeviceID                            string   `json:"device_id"`
	OwnerRevision                       uint64   `json:"owner_revision"`
}

type RunConfig struct {
	QualificationID                   string
	Environment                       string
	DevelopmentOnly                   bool
	DeploymentID                      string
	OCIReleaseID                      string
	Services                          []string
	Authority                         string
	NetworkAddress                    string
	EndpointAuthoritySHA256           string
	ConfigSHA256                      string
	ToolSHA256                        string
	KubernetesDeploymentReceiptSHA256 string
	KubernetesAdmissionReceiptSHA256  string
	ControlplanePodBindingSHA256      string
	CurrentClientCertificateSHA256    string
	NextClientCertificateSHA256       string
	RevokedClientCertificateSHA256    string
	ExpectedServerLeafSHA256          string
	CurrentClient                     *http.Client
	NextClient                        *http.Client
	AnonymousTLS                      *tls.Config
	RevokedTLS                        *tls.Config
	WrongServerNameTLS                *tls.Config
	Actor                             actionconsent.Actor
}

type Runner struct {
	now func() time.Time
}

func NewRunner() *Runner { return &Runner{now: time.Now} }

func LoadLiveConfig(path string, timeout time.Duration) (RunConfig, error) {
	payload, err := readRegular(path, maximumConfigBytes, true)
	if err != nil {
		return RunConfig{}, fmt.Errorf("mTLS dispatch config: %w", err)
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return RunConfig{}, fmt.Errorf("mTLS dispatch config contains duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document liveConfigDocument
	if err := decoder.Decode(&document); err != nil {
		return RunConfig{}, fmt.Errorf("mTLS dispatch config JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || document.Schema != 1 ||
		!document.AcknowledgeLiveDispatch || timeout < 100*time.Millisecond ||
		timeout > 2*time.Second {
		return RunConfig{}, fmt.Errorf("mTLS dispatch config fields are invalid")
	}
	if !auth.ValidIdentifier(document.QualificationID, 64) ||
		(document.Environment != "staging" && document.Environment != "production") ||
		!auth.ValidIdentifier(document.DeploymentID, 64) ||
		!auth.ValidIdentifier(document.OCIReleaseID, 64) ||
		!equalServices(document.Services) ||
		!validSHA256(document.ExpectedServerLeafCertificateSHA256) {
		return RunConfig{}, fmt.Errorf("mTLS dispatch config identity is invalid")
	}
	for _, path := range []string{document.ServerCAFile,
		document.CurrentClientCertificateFile, document.CurrentClientKeyFile,
		document.NextClientCertificateFile, document.NextClientKeyFile,
		document.RevokedClientCertificateFile, document.RevokedClientKeyFile,
		document.KubernetesDeploymentReceiptFile,
		document.KubernetesAdmissionReceiptFile,
		document.ControlplanePodUIDFile} {
		if !filepath.IsAbs(path) {
			return RunConfig{}, fmt.Errorf("mTLS dispatch config paths must be absolute")
		}
	}
	parsed, err := url.Parse(document.Endpoint)
	expectedHost := document.DeploymentID + "-accountauthorization"
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != expectedHost ||
		parsed.Port() != "9444" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != document.Endpoint {
		return RunConfig{}, fmt.Errorf("mTLS dispatch endpoint is not the exact accountauthorization service")
	}
	serverCAPEM, err := readRegular(document.ServerCAFile, 64*1024, false)
	if err != nil {
		return RunConfig{}, fmt.Errorf("mTLS dispatch server CA is invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverCAPEM) {
		return RunConfig{}, fmt.Errorf("mTLS dispatch server CA is invalid")
	}
	current, currentTLS, currentDigest, err := loadClient(
		serverCAPEM, roots, document.CurrentClientCertificateFile,
		document.CurrentClientKeyFile, timeout, parsed.Hostname())
	if err != nil {
		return RunConfig{}, err
	}
	next, _, nextDigest, err := loadClient(serverCAPEM, roots,
		document.NextClientCertificateFile, document.NextClientKeyFile,
		timeout, parsed.Hostname())
	if err != nil {
		return RunConfig{}, err
	}
	_, revokedTLS, revokedDigest, err := loadClient(serverCAPEM, roots,
		document.RevokedClientCertificateFile,
		document.RevokedClientKeyFile, timeout, parsed.Hostname())
	if err != nil {
		return RunConfig{}, err
	}
	if currentDigest == nextDigest || currentDigest == revokedDigest ||
		nextDigest == revokedDigest {
		return RunConfig{}, fmt.Errorf("mTLS dispatch client identities must be distinct")
	}
	deploymentSHA, err := DigestRegularFile(
		document.KubernetesDeploymentReceiptFile, maximumDocumentBytes)
	if err != nil {
		return RunConfig{}, fmt.Errorf("Kubernetes deployment receipt is invalid")
	}
	admissionSHA, err := DigestRegularFile(
		document.KubernetesAdmissionReceiptFile, maximumDocumentBytes)
	if err != nil {
		return RunConfig{}, fmt.Errorf("Kubernetes admission receipt is invalid")
	}
	podUID, err := readRegular(document.ControlplanePodUIDFile, 1024, true)
	if err != nil || len(bytes.TrimSpace(podUID)) != len(podUID) ||
		!auth.ValidIdentifier(string(podUID), 128) {
		return RunConfig{}, fmt.Errorf("controlplane Pod UID is invalid")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(
		document.QualificationNonce)
	if err != nil || len(nonce) != 16 ||
		base64.RawURLEncoding.EncodeToString(nonce) != document.QualificationNonce {
		return RunConfig{}, fmt.Errorf("mTLS dispatch qualification nonce is invalid")
	}
	actor := actionconsent.Actor{TenantID: document.TenantID,
		OwnerID: document.Subject, DeviceID: document.DeviceID,
		OwnerRevision: document.OwnerRevision}
	if !accountauth.ValidPrincipal(accountauth.Principal{
		TenantID: actor.TenantID, Subject: actor.OwnerID}) ||
		!auth.ValidIdentifier(actor.DeviceID, 64) ||
		!accountauth.ValidAccountRevision(actor.OwnerRevision) {
		return RunConfig{}, fmt.Errorf("mTLS dispatch qualification actor is invalid")
	}
	configDigest := sha256.Sum256(payload)
	podDigest := sha256.Sum256(append(append(
		[]byte(podBindingDomain), nonce...), podUID...))
	endpointDigest := sha256.Sum256(append(
		[]byte(endpointDomain), []byte(document.Endpoint)...))
	anonymousTLS := currentTLS.Clone()
	anonymousTLS.Certificates = nil
	wrongNameTLS := currentTLS.Clone()
	wrongNameTLS.ServerName = "invalid.invalid"
	return RunConfig{
		QualificationID: document.QualificationID,
		Environment:     document.Environment, DeploymentID: document.DeploymentID,
		OCIReleaseID: document.OCIReleaseID,
		Services:     append([]string(nil), document.Services...),
		Authority:    document.Endpoint, NetworkAddress: parsed.Host,
		EndpointAuthoritySHA256:           hex.EncodeToString(endpointDigest[:]),
		ConfigSHA256:                      hex.EncodeToString(configDigest[:]),
		KubernetesDeploymentReceiptSHA256: deploymentSHA,
		KubernetesAdmissionReceiptSHA256:  admissionSHA,
		ControlplanePodBindingSHA256:      hex.EncodeToString(podDigest[:]),
		CurrentClientCertificateSHA256:    currentDigest,
		NextClientCertificateSHA256:       nextDigest,
		RevokedClientCertificateSHA256:    revokedDigest,
		ExpectedServerLeafSHA256:          document.ExpectedServerLeafCertificateSHA256,
		CurrentClient:                     current, NextClient: next,
		AnonymousTLS: anonymousTLS, RevokedTLS: revokedTLS,
		WrongServerNameTLS: wrongNameTLS, Actor: actor,
	}, nil
}

func loadClient(caPEM []byte, roots *x509.CertPool, certificatePath,
	keyPath string, timeout time.Duration, serverName string) (
	*http.Client, *tls.Config, string, error) {
	certificatePEM, err := readRegular(certificatePath, 64*1024, false)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mTLS dispatch client certificate is invalid")
	}
	keyPEM, err := readRegular(keyPath, 64*1024, true)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mTLS dispatch client key is invalid")
	}
	client, err := auth.NewCompanionIntrospectionMTLSClient(
		caPEM, certificatePEM, keyPEM, timeout)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mTLS dispatch client identity is invalid")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, nil, "", fmt.Errorf("mTLS dispatch client identity is invalid")
	}
	if !certificatePEMMatchesChain(certificatePEM, certificate.Certificate) {
		return nil, nil, "", fmt.Errorf("mTLS dispatch client certificate chain is invalid")
	}
	digest := sha256.Sum256(certificate.Certificate[0])
	configuration := &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{certificate},
		ServerName: serverName, NextProtos: []string{HTTP2Protocol}}
	return client, configuration, hex.EncodeToString(digest[:]), nil
}

func certificatePEMMatchesChain(payload []byte, chain [][]byte) bool {
	if len(chain) == 0 {
		return false
	}
	rest := payload
	for _, expected := range chain {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" ||
			!bytes.Equal(block.Bytes, expected) {
			return false
		}
		rest = remaining
	}
	return len(bytes.TrimSpace(rest)) == 0
}

func (runner *Runner) Run(ctx context.Context, config RunConfig) (
	Observation, error) {
	if runner == nil || runner.now == nil || ctx == nil || !validRunConfig(config) {
		return Observation{}, fmt.Errorf("invalid mTLS dispatch run configuration")
	}
	started := runner.now().UTC().Truncate(time.Second)
	currentEvidence, currentLatency, err := positiveProbe(
		ctx, runner.now, config.CurrentClient, config.Authority, config.Actor)
	if err != nil || currentEvidence.ServerLeafCertSHA256 !=
		config.ExpectedServerLeafSHA256 {
		return Observation{}, fmt.Errorf("current mTLS dispatch failed")
	}
	nextEvidence, nextLatency, err := positiveProbe(
		ctx, runner.now, config.NextClient, config.Authority, config.Actor)
	if err != nil || nextEvidence.ServerLeafCertSHA256 !=
		config.ExpectedServerLeafSHA256 ||
		nextEvidence != currentEvidence {
		return Observation{}, fmt.Errorf("next mTLS dispatch failed")
	}
	if !rejectedTLSHandshake(ctx, config.NetworkAddress, config.AnonymousTLS) {
		return Observation{}, fmt.Errorf("anonymous mTLS client was not rejected")
	}
	if !rejectedTLSHandshake(ctx, config.NetworkAddress, config.RevokedTLS) {
		return Observation{}, fmt.Errorf("revoked mTLS client was not rejected")
	}
	if !rejectedServerName(ctx, config.NetworkAddress,
		config.WrongServerNameTLS) {
		return Observation{}, fmt.Errorf("wrong mTLS server name was not rejected")
	}
	confirmation, _, err := positiveProbe(ctx, runner.now,
		config.CurrentClient, config.Authority, config.Actor)
	if err != nil || confirmation != currentEvidence {
		return Observation{}, fmt.Errorf("mTLS dispatch availability confirmation failed")
	}
	finished := runner.now().UTC().Truncate(time.Second)
	observation := Observation{Schema: ObservationSchema,
		QualificationID: config.QualificationID,
		Environment:     config.Environment, DevelopmentOnly: config.DevelopmentOnly,
		DeploymentID: config.DeploymentID, OCIReleaseID: config.OCIReleaseID,
		Services:                          append([]string(nil), config.Services...),
		EndpointAuthoritySHA256:           config.EndpointAuthoritySHA256,
		ConfigSHA256:                      config.ConfigSHA256,
		QualificationToolSHA256:           config.ToolSHA256,
		KubernetesDeploymentReceiptSHA256: config.KubernetesDeploymentReceiptSHA256,
		KubernetesAdmissionReceiptSHA256:  config.KubernetesAdmissionReceiptSHA256,
		ControlplanePodBindingSHA256:      config.ControlplanePodBindingSHA256,
		CurrentClientCertificateSHA256:    config.CurrentClientCertificateSHA256,
		NextClientCertificateSHA256:       config.NextClientCertificateSHA256,
		RevokedClientCertificateSHA256:    config.RevokedClientCertificateSHA256,
		ServerLeafCertificateSHA256:       currentEvidence.ServerLeafCertSHA256,
		TLSVersion:                        TLSVersion13, NegotiatedProtocol: currentEvidence.NegotiatedProtocol,
		WakeContract:              pushdelivery.PrivateWakeContract,
		CurrentCredentialAccepted: true, NextCredentialAccepted: true,
		AnonymousClientRejected: true, RevokedClientRejected: true,
		WrongServerNameRejected: true, CurrentLatencyMS: currentLatency,
		NextLatencyMS: nextLatency, StartedAt: started.Format(time.RFC3339),
		FinishedAt: finished.Format(time.RFC3339), SecretFree: true}
	if err := validateObservation(observation); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func positiveProbe(ctx context.Context, now func() time.Time,
	httpClient *http.Client, authority string, actor actionconsent.Actor) (
	pushdelivery.PrivateWakeTransportEvidence, int64, error) {
	client, err := pushdelivery.NewMTLSWakeClient(authority, httpClient)
	if err != nil {
		return pushdelivery.PrivateWakeTransportEvidence{}, 0, err
	}
	probeContext, cancel := context.WithTimeout(ctx, maximumProbeTime)
	defer cancel()
	started := now().UTC()
	disposition, evidence, err := client.SendWakeWithTransportEvidence(
		probeContext, actor, actionconsent.WakeContract,
		actionconsent.CanonicalWakePayload())
	finished := now().UTC()
	if err != nil || disposition != actionconsent.WakeSendAccepted ||
		finished.Before(started) || finished.Sub(started) > maximumProbeTime ||
		evidence.TLSVersion != tls.VersionTLS13 ||
		evidence.NegotiatedProtocol != HTTP2Protocol ||
		!validSHA256(evidence.ServerLeafCertSHA256) {
		return pushdelivery.PrivateWakeTransportEvidence{}, 0,
			fmt.Errorf("authenticated private wake was not accepted")
	}
	return evidence, finished.Sub(started).Milliseconds(), nil
}

func rejectedTLSHandshake(ctx context.Context, address string,
	configuration *tls.Config) bool {
	probeContext, cancel := context.WithTimeout(ctx, maximumProbeTime)
	defer cancel()
	connection, err := (&tls.Dialer{Config: configuration.Clone()}).DialContext(
		probeContext, "tcp", address)
	if connection != nil {
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1)
			_, err = connection.Read(buffer)
		}
		_ = connection.Close()
	}
	return isAuthenticatedRejection(err)
}

func rejectedServerName(ctx context.Context, address string,
	configuration *tls.Config) bool {
	probeContext, cancel := context.WithTimeout(ctx, maximumProbeTime)
	defer cancel()
	connection, err := (&tls.Dialer{Config: configuration.Clone()}).DialContext(
		probeContext, "tcp", address)
	if connection != nil {
		_ = connection.Close()
	}
	var verification *tls.CertificateVerificationError
	var hostname x509.HostnameError
	return err != nil && (errors.As(err, &verification) || errors.As(err, &hostname))
}

func isAuthenticatedRejection(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return false
	}
	text := strings.ToLower(err.Error())
	for _, forbidden := range []string{"connection refused", "no route to host",
		"network is unreachable", "server misbehaving"} {
		if strings.Contains(text, forbidden) {
			return false
		}
	}
	return true
}

func validRunConfig(config RunConfig) bool {
	principal := accountauth.Principal{TenantID: config.Actor.TenantID,
		Subject: config.Actor.OwnerID}
	return auth.ValidIdentifier(config.QualificationID, 64) &&
		(config.Environment == "staging" || config.Environment == "production") &&
		(!config.DevelopmentOnly || config.Environment == "staging") &&
		auth.ValidIdentifier(config.DeploymentID, 64) &&
		auth.ValidIdentifier(config.OCIReleaseID, 64) && equalServices(config.Services) &&
		config.Authority != "" && config.NetworkAddress != "" &&
		validSHA256(config.EndpointAuthoritySHA256) &&
		validSHA256(config.ConfigSHA256) && validSHA256(config.ToolSHA256) &&
		validSHA256(config.KubernetesDeploymentReceiptSHA256) &&
		validSHA256(config.KubernetesAdmissionReceiptSHA256) &&
		validSHA256(config.ControlplanePodBindingSHA256) &&
		validSHA256(config.CurrentClientCertificateSHA256) &&
		validSHA256(config.NextClientCertificateSHA256) &&
		validSHA256(config.RevokedClientCertificateSHA256) &&
		validSHA256(config.ExpectedServerLeafSHA256) &&
		config.CurrentClientCertificateSHA256 != config.NextClientCertificateSHA256 &&
		config.CurrentClientCertificateSHA256 != config.RevokedClientCertificateSHA256 &&
		config.NextClientCertificateSHA256 != config.RevokedClientCertificateSHA256 &&
		config.CurrentClient != nil && config.NextClient != nil &&
		config.AnonymousTLS != nil && config.RevokedTLS != nil &&
		config.WrongServerNameTLS != nil && accountauth.ValidPrincipal(principal) &&
		auth.ValidIdentifier(config.Actor.DeviceID, 64) &&
		accountauth.ValidAccountRevision(config.Actor.OwnerRevision)
}

func equalServices(services []string) bool {
	if len(services) != len(ExactServices) {
		return false
	}
	for index := range ExactServices {
		if services[index] != ExactServices[index] {
			return false
		}
	}
	return true
}
