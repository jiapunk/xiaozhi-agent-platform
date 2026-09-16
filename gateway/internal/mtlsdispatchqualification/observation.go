package mtlsdispatchqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ObservationSchema = 1
	TLSVersion13      = "TLS1.3"
	HTTP2Protocol     = "h2"
	maximumProbeTime  = 15 * time.Second
	maximumRunTime    = 2 * time.Minute
)

var ExactServices = []string{
	"gateway",
	"controlplane",
	"agentproxy",
	"firmwareorigin",
	"generationcoordinator",
	"accountauthorization",
	"factorytimeauthority",
}

type Observation struct {
	Schema                            uint32   `json:"schema"`
	QualificationID                   string   `json:"qualification_id"`
	Environment                       string   `json:"environment"`
	DevelopmentOnly                   bool     `json:"development_only"`
	DeploymentID                      string   `json:"deployment_id"`
	OCIReleaseID                      string   `json:"oci_release_id"`
	Services                          []string `json:"services"`
	EndpointAuthoritySHA256           string   `json:"endpoint_authority_sha256"`
	ConfigSHA256                      string   `json:"config_sha256"`
	QualificationToolSHA256           string   `json:"qualification_tool_sha256"`
	KubernetesDeploymentReceiptSHA256 string   `json:"kubernetes_deployment_receipt_sha256"`
	KubernetesAdmissionReceiptSHA256  string   `json:"kubernetes_admission_receipt_sha256"`
	ControlplanePodBindingSHA256      string   `json:"controlplane_pod_binding_sha256"`
	CurrentClientCertificateSHA256    string   `json:"current_client_certificate_sha256"`
	NextClientCertificateSHA256       string   `json:"next_client_certificate_sha256"`
	RevokedClientCertificateSHA256    string   `json:"revoked_client_certificate_sha256"`
	ServerLeafCertificateSHA256       string   `json:"server_leaf_certificate_sha256"`
	TLSVersion                        string   `json:"tls_version"`
	NegotiatedProtocol                string   `json:"negotiated_protocol"`
	WakeContract                      string   `json:"wake_contract"`
	CurrentCredentialAccepted         bool     `json:"current_credential_accepted"`
	NextCredentialAccepted            bool     `json:"next_credential_accepted"`
	AnonymousClientRejected           bool     `json:"anonymous_client_rejected"`
	RevokedClientRejected             bool     `json:"revoked_client_rejected"`
	WrongServerNameRejected           bool     `json:"wrong_server_name_rejected"`
	CurrentLatencyMS                  int64    `json:"current_latency_ms"`
	NextLatencyMS                     int64    `json:"next_latency_ms"`
	StartedAt                         string   `json:"started_at"`
	FinishedAt                        string   `json:"finished_at"`
	SecretFree                        bool     `json:"secret_free"`
}

func LoadObservation(path string) (Observation, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return Observation{}, nil, fmt.Errorf("mTLS dispatch observation: %w", err)
	}
	observation, err := ParseObservation(payload)
	if err != nil {
		return Observation{}, nil, err
	}
	return observation, payload, nil
}

func ParseObservation(payload []byte) (Observation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Observation{}, fmt.Errorf("mTLS dispatch observation JSON is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, fmt.Errorf("mTLS dispatch observation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Observation{}, fmt.Errorf("mTLS dispatch observation has trailing JSON")
	}
	canonical, err := CanonicalObservation(observation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Observation{}, fmt.Errorf("mTLS dispatch observation is not canonical JSON")
	}
	if err := validateObservation(observation); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func CanonicalObservation(observation Observation) ([]byte, error) {
	payload, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func validateObservation(observation Observation) error {
	if observation.Schema != ObservationSchema ||
		!auth.ValidIdentifier(observation.QualificationID, 64) ||
		(observation.Environment != "staging" &&
			observation.Environment != "production") ||
		(observation.DevelopmentOnly && observation.Environment != "staging") ||
		!auth.ValidIdentifier(observation.DeploymentID, 64) ||
		!auth.ValidIdentifier(observation.OCIReleaseID, 64) ||
		!reflect.DeepEqual(observation.Services, ExactServices) ||
		!validSHA256(observation.EndpointAuthoritySHA256) ||
		!validSHA256(observation.ConfigSHA256) ||
		!validSHA256(observation.QualificationToolSHA256) ||
		!validSHA256(observation.KubernetesDeploymentReceiptSHA256) ||
		!validSHA256(observation.KubernetesAdmissionReceiptSHA256) ||
		!validSHA256(observation.ControlplanePodBindingSHA256) ||
		!validSHA256(observation.CurrentClientCertificateSHA256) ||
		!validSHA256(observation.NextClientCertificateSHA256) ||
		!validSHA256(observation.RevokedClientCertificateSHA256) ||
		!validSHA256(observation.ServerLeafCertificateSHA256) ||
		observation.CurrentClientCertificateSHA256 ==
			observation.NextClientCertificateSHA256 ||
		observation.CurrentClientCertificateSHA256 ==
			observation.RevokedClientCertificateSHA256 ||
		observation.NextClientCertificateSHA256 ==
			observation.RevokedClientCertificateSHA256 ||
		observation.TLSVersion != TLSVersion13 ||
		observation.NegotiatedProtocol != HTTP2Protocol ||
		observation.WakeContract != pushdelivery.PrivateWakeContract ||
		!observation.CurrentCredentialAccepted ||
		!observation.NextCredentialAccepted ||
		!observation.AnonymousClientRejected ||
		!observation.RevokedClientRejected ||
		!observation.WrongServerNameRejected || !observation.SecretFree ||
		observation.CurrentLatencyMS < 0 ||
		observation.CurrentLatencyMS > maximumProbeTime.Milliseconds() ||
		observation.NextLatencyMS < 0 ||
		observation.NextLatencyMS > maximumProbeTime.Milliseconds() {
		return fmt.Errorf("mTLS dispatch observation fields are invalid")
	}
	started, err := time.Parse(time.RFC3339, observation.StartedAt)
	if err != nil || started.Format(time.RFC3339) != observation.StartedAt {
		return fmt.Errorf("mTLS dispatch observation start time is invalid")
	}
	finished, err := time.Parse(time.RFC3339, observation.FinishedAt)
	if err != nil || finished.Format(time.RFC3339) != observation.FinishedAt ||
		finished.Before(started) || finished.Sub(started) > maximumRunTime {
		return fmt.Errorf("mTLS dispatch observation finish time is invalid")
	}
	return nil
}
