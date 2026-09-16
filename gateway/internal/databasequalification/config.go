package databasequalification

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const maximumConfigBytes = int64(64 * 1024)

type liveFailoverConfigDocument struct {
	Schema                             uint32                         `json:"schema"`
	QualificationID                    string                         `json:"qualification_id"`
	Environment                        string                         `json:"environment"`
	RunNonceB64URL                     string                         `json:"run_nonce_b64url"`
	AcknowledgeManagedDatabaseFailover bool                           `json:"acknowledge_managed_database_failover"`
	Databases                          []liveFailoverDatabaseDocument `json:"databases"`
}

type liveFailoverDatabaseDocument struct {
	Role             Role   `json:"role"`
	ManagedClusterID string `json:"managed_cluster_id"`
	DatabaseURL      string `json:"database_url"`
}

type liveRestoreConfigDocument struct {
	Schema                                uint32                        `json:"schema"`
	QualificationID                       string                        `json:"qualification_id"`
	Environment                           string                        `json:"environment"`
	RunNonceB64URL                        string                        `json:"run_nonce_b64url"`
	AcknowledgeIsolatedPointInTimeRestore bool                          `json:"acknowledge_isolated_point_in_time_restore"`
	Databases                             []liveRestoreDatabaseDocument `json:"databases"`
}

type liveRestoreDatabaseDocument struct {
	Role                    Role   `json:"role"`
	ManagedClusterID        string `json:"managed_cluster_id"`
	RestoreOperationID      string `json:"restore_operation_id"`
	RequestedRecoveryTarget string `json:"requested_recovery_target"`
	RestoreDatabaseURL      string `json:"restore_database_url"`
}

func LoadLiveFailoverConfig(path, qualificationToolPath string,
	operationTimeout, heartbeatInterval,
	failoverTimeout time.Duration) (FailoverRunConfig, error) {
	payload, err := readRegular(path, maximumConfigBytes, true)
	if err != nil {
		return FailoverRunConfig{}, fmt.Errorf("managed database failover config rejected")
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return FailoverRunConfig{}, fmt.Errorf("managed database failover config is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document liveFailoverConfigDocument
	if err := decoder.Decode(&document); err != nil {
		return FailoverRunConfig{}, fmt.Errorf("managed database failover config JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF ||
		document.Schema != 1 ||
		!document.AcknowledgeManagedDatabaseFailover ||
		(document.Environment != "staging" && document.Environment != "production") ||
		!auth.ValidIdentifier(document.QualificationID, 64) ||
		len(document.Databases) != len(ExactRoles) ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 10*time.Second ||
		heartbeatInterval < 100*time.Millisecond || heartbeatInterval > 30*time.Second ||
		failoverTimeout < minimumFailoverTimeout || failoverTimeout > maximumFailoverTimeout {
		return FailoverRunConfig{}, fmt.Errorf("managed database failover config fields are invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(document.RunNonceB64URL)
	if err != nil || len(nonce) != 16 ||
		base64.RawURLEncoding.EncodeToString(nonce) != document.RunNonceB64URL {
		return FailoverRunConfig{}, fmt.Errorf("managed database failover nonce is invalid")
	}
	toolSHA, err := DigestRegularFile(qualificationToolPath, 128<<20)
	if err != nil {
		return FailoverRunConfig{}, fmt.Errorf("managed database qualification tool rejected")
	}
	config := FailoverRunConfig{
		QualificationID:   document.QualificationID,
		Environment:       document.Environment,
		ConfigSHA256:      digestBytes(payload),
		ToolSHA256:        toolSHA,
		Nonce:             append([]byte(nil), nonce...),
		HeartbeatInterval: heartbeatInterval,
		FailoverTimeout:   failoverTimeout,
		Candidates:        make([]DatabaseCandidate, 0, len(ExactRoles)),
	}
	seenAuthorities := make(map[string]bool, len(ExactRoles))
	for index, database := range document.Databases {
		if database.Role != ExactRoles[index] ||
			!auth.ValidIdentifier(database.ManagedClusterID, 128) ||
			!validManagedDatabaseURL(database.DatabaseURL) {
			closeCandidates(config.Candidates)
			return FailoverRunConfig{}, fmt.Errorf("managed database failover database identity is invalid")
		}
		authoritySHA, err := endpointAuthoritySHA256(database.DatabaseURL)
		if err != nil || seenAuthorities[authoritySHA] {
			closeCandidates(config.Candidates)
			return FailoverRunConfig{}, fmt.Errorf("managed database failover endpoints must be distinct")
		}
		seenAuthorities[authoritySHA] = true
		store, err := OpenStore(database.DatabaseURL, database.Role, operationTimeout)
		if err != nil {
			closeCandidates(config.Candidates)
			return FailoverRunConfig{}, fmt.Errorf("managed database failover connection rejected")
		}
		config.Candidates = append(config.Candidates, DatabaseCandidate{
			Role: database.Role, ManagedClusterID: database.ManagedClusterID,
			EndpointAuthoritySHA256: authoritySHA, Store: store,
		})
	}
	config.RunBindingSHA256 = runBindingSHA256(config)
	if !validFailoverRunIdentity(config) {
		closeCandidates(config.Candidates)
		return FailoverRunConfig{}, fmt.Errorf("managed database failover configuration is invalid")
	}
	return config, nil
}

func endpointAuthoritySHA256(databaseURL string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Hostname() == "" || parsed.Path == "" {
		return "", fmt.Errorf("invalid managed database endpoint authority")
	}
	port := parsed.Port()
	if port == "" {
		port = "5432"
	}
	payload := []byte("XIAOZHI-M73-MANAGED-DATABASE-ENDPOINT-V1\x00" +
		parsed.Hostname() + "\x00" + port + "\x00" + parsed.EscapedPath())
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func runBindingSHA256(config FailoverRunConfig) string {
	hash := sha256.New()
	hash.Write([]byte("XIAOZHI-M73-MANAGED-DATABASE-RUN-V1\x00"))
	hash.Write(config.Nonce)
	hash.Write([]byte(config.QualificationID))
	hash.Write([]byte{0})
	hash.Write([]byte(config.Environment))
	hash.Write([]byte{0})
	hash.Write([]byte(config.ConfigSHA256))
	for _, candidate := range config.Candidates {
		hash.Write([]byte{0})
		hash.Write([]byte(candidate.Role))
		hash.Write([]byte{0})
		hash.Write([]byte(candidate.ManagedClusterID))
		hash.Write([]byte{0})
		hash.Write([]byte(candidate.EndpointAuthoritySHA256))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func closeCandidates(candidates []DatabaseCandidate) {
	for _, candidate := range candidates {
		if candidate.Store != nil {
			_ = candidate.Store.Close()
		}
	}
}

func CloseFailoverConfig(config FailoverRunConfig) {
	closeCandidates(config.Candidates)
}

func LoadLiveRestoreConfig(path, failoverObservationPath,
	qualificationToolPath string, operationTimeout time.Duration) (
	RestoreRunConfig, error) {
	failover, failoverPayload, err := LoadFailoverObservation(failoverObservationPath)
	if err != nil || failover.DevelopmentOnly {
		return RestoreRunConfig{}, fmt.Errorf("live managed database failover observation rejected")
	}
	payload, err := readRegular(path, maximumConfigBytes, true)
	if err != nil {
		return RestoreRunConfig{}, fmt.Errorf("managed database restore config rejected")
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return RestoreRunConfig{}, fmt.Errorf("managed database restore config is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document liveRestoreConfigDocument
	if err := decoder.Decode(&document); err != nil {
		return RestoreRunConfig{}, fmt.Errorf("managed database restore config JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || document.Schema != 1 ||
		!document.AcknowledgeIsolatedPointInTimeRestore ||
		document.QualificationID != failover.QualificationID ||
		document.Environment != failover.Environment ||
		len(document.Databases) != len(ExactRoles) ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 10*time.Second {
		return RestoreRunConfig{}, fmt.Errorf("managed database restore config fields are invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(document.RunNonceB64URL)
	if err != nil || len(nonce) != 16 ||
		base64.RawURLEncoding.EncodeToString(nonce) != document.RunNonceB64URL {
		return RestoreRunConfig{}, fmt.Errorf("managed database restore nonce is invalid")
	}
	toolSHA, err := DigestRegularFile(qualificationToolPath, 128<<20)
	if err != nil {
		return RestoreRunConfig{}, fmt.Errorf("managed database qualification tool rejected")
	}
	config := RestoreRunConfig{QualificationID: document.QualificationID,
		Environment: document.Environment, ConfigSHA256: digestBytes(payload),
		ToolSHA256: toolSHA, FailoverObservationSHA256: digestBytes(failoverPayload),
		RunBindingSHA256: failover.RunBindingSHA256,
		Nonce:            append([]byte(nil), nonce...), Candidates: make([]RestoreDatabaseCandidate, 0, len(ExactRoles))}
	seenRestoreEndpoints := make(map[string]bool, len(ExactRoles))
	for index, database := range document.Databases {
		source := failover.Databases[index]
		target, timeErr := parseCanonicalTime(database.RequestedRecoveryTarget)
		marker, markerErr := parseCanonicalTime(source.RestoreMarkerCommittedAt)
		exclusion, exclusionErr := parseCanonicalTime(source.RestoreExclusionCommittedAt)
		if database.Role != ExactRoles[index] || database.Role != source.Role ||
			database.ManagedClusterID != source.ManagedClusterID ||
			!auth.ValidIdentifier(database.RestoreOperationID, 128) ||
			timeErr != nil || markerErr != nil || exclusionErr != nil ||
			!target.After(marker) || !target.Before(exclusion) ||
			!validManagedDatabaseURL(database.RestoreDatabaseURL) {
			closeRestoreCandidates(config.Candidates)
			return RestoreRunConfig{}, fmt.Errorf("managed database restore identity is invalid")
		}
		authoritySHA, digestErr := endpointAuthoritySHA256(database.RestoreDatabaseURL)
		if digestErr != nil || authoritySHA == source.EndpointAuthoritySHA256 ||
			seenRestoreEndpoints[authoritySHA] {
			closeRestoreCandidates(config.Candidates)
			return RestoreRunConfig{}, fmt.Errorf("managed database restore endpoints are not isolated")
		}
		seenRestoreEndpoints[authoritySHA] = true
		store, openErr := OpenStore(database.RestoreDatabaseURL, database.Role,
			operationTimeout)
		if openErr != nil {
			closeRestoreCandidates(config.Candidates)
			return RestoreRunConfig{}, fmt.Errorf("managed database restore connection rejected")
		}
		config.Candidates = append(config.Candidates, RestoreDatabaseCandidate{
			Role: database.Role, ManagedClusterID: database.ManagedClusterID,
			RestoreOperationID:             database.RestoreOperationID,
			RequestedRecoveryTarget:        target,
			SourceEndpointAuthoritySHA256:  source.EndpointAuthoritySHA256,
			RestoreEndpointAuthoritySHA256: authoritySHA,
			MarkerCommittedAt:              marker, ExclusionCommittedAt: exclusion,
			Store: store,
		})
	}
	sourceCandidates := make([]DatabaseCandidate, len(failover.Databases))
	for index, evidence := range failover.Databases {
		sourceCandidates[index] = DatabaseCandidate{Role: evidence.Role,
			ManagedClusterID:        evidence.ManagedClusterID,
			EndpointAuthoritySHA256: evidence.EndpointAuthoritySHA256}
	}
	computed := runBindingSHA256(FailoverRunConfig{
		QualificationID: config.QualificationID, Environment: config.Environment,
		ConfigSHA256: failover.ConfigSHA256, Nonce: config.Nonce,
		Candidates: sourceCandidates})
	if computed != config.RunBindingSHA256 || !validRestoreRunConfig(config) {
		closeRestoreCandidates(config.Candidates)
		return RestoreRunConfig{}, fmt.Errorf("managed database restore run binding is invalid")
	}
	return config, nil
}

func closeRestoreCandidates(candidates []RestoreDatabaseCandidate) {
	for _, candidate := range candidates {
		if candidate.Store != nil {
			_ = candidate.Store.Close()
		}
	}
}

func CloseRestoreConfig(config RestoreRunConfig) {
	closeRestoreCandidates(config.Candidates)
}
