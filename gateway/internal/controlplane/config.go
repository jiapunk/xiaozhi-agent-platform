package controlplane

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/identityconfig"
)

type Settings struct {
	Address                            string
	TLSCertFile                        string
	TLSKeyFile                         string
	AllowInsecure                      bool
	Identity                           identityconfig.Settings
	PublicDeviceWSS                    string
	VoiceTokenKey                      []byte
	AgentTokenKey                      []byte
	VoiceTokenKeyring                  *auth.ManagedTokenKeyring
	AgentTokenKeyring                  *auth.ManagedTokenKeyring
	VoiceTokenTTL                      time.Duration
	AgentTokenTTL                      time.Duration
	ProofMaxSkew                       time.Duration
	ProofMinInterval                   time.Duration
	OTAReleaseRegistryFile             string
	OTATokenKey                        []byte
	OTATokenKeyring                    *auth.ManagedTokenKeyring
	OTARolloutKey                      []byte
	OTATokenTTL                        time.Duration
	Generation                         generation.ReplicaSettings
	DeviceClaimEnabled                 bool
	AppTokenKeys                       [][]byte
	AppTokenEd25519Keys                map[string]ed25519.PublicKey
	AppTokenIssuer                     string
	AppTokenMaxTTL                     time.Duration
	AppTokenIntrospectionURL           string
	AppTokenIntrospectionCA            string
	AppTokenIntrospectionCert          string
	AppTokenIntrospectionKey           string
	AppTokenIntrospectionTimeout       time.Duration
	ServiceEntitlementAuthorizationURL string
	DeviceClaimTTL                     time.Duration
	DeviceClaimMaxPending              int
	ActionConsentEnabled               bool
	ActionConsentReference             bool
	ActionConsentMaxPending            int
	ActionConsentPushEnabled           bool
	ActionConsentPushWorkerID          string
	ActionConsentPushPoll              time.Duration
	ActionConsentPushLease             time.Duration
	ActionConsentPushRetry             time.Duration
	ActionConsentPushTimeout           time.Duration
	OwnershipDatabaseURL               string
	OwnershipDatabaseMax               int
	OwnershipDatabaseIdle              int
	OwnershipDatabaseConnTTL           time.Duration
	OwnershipDatabaseTimeout           time.Duration
}

func LoadSettings() (Settings, error) {
	settings := Settings{
		Address:          envOr("CONTROL_PLANE_ADDRESS", ":8444"),
		TLSCertFile:      os.Getenv("CONTROL_TLS_CERT_FILE"),
		TLSKeyFile:       os.Getenv("CONTROL_TLS_KEY_FILE"),
		PublicDeviceWSS:  os.Getenv("PUBLIC_DEVICE_WSS_URL"),
		VoiceTokenTTL:    15 * time.Minute,
		AgentTokenTTL:    10 * time.Minute,
		ProofMaxSkew:     time.Minute,
		ProofMinInterval: 5 * time.Second,
		OTATokenTTL:      5 * time.Minute,
	}
	var err error
	if settings.AllowInsecure, err = parseBool(
		"ALLOW_INSECURE_DEVELOPMENT", false); err != nil {
		return Settings{}, err
	}
	if err := validatePublicWSS(settings.PublicDeviceWSS,
		settings.AllowInsecure); err != nil {
		return Settings{}, err
	}
	if !settings.AllowInsecure &&
		(settings.TLSCertFile == "" || settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("control-plane TLS certificate and key are required")
	}
	if (settings.TLSCertFile == "") != (settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("control-plane TLS certificate and key must be configured together")
	}
	settings.Identity, err = identityconfig.Load(settings.AllowInsecure, true)
	if err != nil {
		return Settings{}, err
	}
	settings.VoiceTokenKeyring, settings.VoiceTokenKey, err =
		loadIssuanceTokenKeyring("voice", "VOICE_TOKEN_HMAC_KEYRING_FILE",
			"VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION",
			"VOICE_TOKEN_HMAC_KEY_B64", settings.AllowInsecure)
	if err != nil {
		return Settings{}, err
	}
	settings.AgentTokenKeyring, settings.AgentTokenKey, err =
		loadIssuanceTokenKeyring("Agent", "AGENT_TOKEN_HMAC_KEYRING_FILE",
			"AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION",
			"AGENT_TOKEN_HMAC_KEY_B64", settings.AllowInsecure)
	if err != nil {
		return Settings{}, err
	}
	if (settings.VoiceTokenKeyring == nil) !=
		(settings.AgentTokenKeyring == nil) {
		return Settings{}, fmt.Errorf("voice and Agent token keyrings must use the same managed mode")
	}
	if settings.VoiceTokenKeyring != nil &&
		!auth.ManagedTokenKeyringsDisjoint(
			settings.VoiceTokenKeyring, settings.AgentTokenKeyring) {
		return Settings{}, fmt.Errorf("voice and Agent managed token keyrings must be disjoint")
	}
	if len(settings.VoiceTokenKey) == len(settings.AgentTokenKey) &&
		len(settings.VoiceTokenKey) != 0 &&
		subtle.ConstantTimeCompare(settings.VoiceTokenKey,
			settings.AgentTokenKey) == 1 {
		return Settings{}, fmt.Errorf("voice and Agent token keys must be distinct")
	}
	appKeyText := os.Getenv("APP_TOKEN_HMAC_KEYS_B64")
	appEd25519Text := os.Getenv("APP_TOKEN_ED25519_KEYRING")
	appIssuerText := os.Getenv("APP_TOKEN_ISSUER")
	appTTLText := os.Getenv("APP_TOKEN_MAX_TTL_SECONDS")
	appIntrospectionURL := os.Getenv("APP_TOKEN_INTROSPECTION_URL")
	appIntrospectionCA := os.Getenv("APP_TOKEN_INTROSPECTION_CA_FILE")
	appIntrospectionCert := os.Getenv("APP_TOKEN_INTROSPECTION_CLIENT_CERT_FILE")
	appIntrospectionKey := os.Getenv("APP_TOKEN_INTROSPECTION_CLIENT_KEY_FILE")
	appIntrospectionTimeout := os.Getenv("APP_TOKEN_INTROSPECTION_TIMEOUT_MS")
	entitlementAuthorizationURL := os.Getenv(
		"SERVICE_ENTITLEMENT_AUTHORIZATION_URL")
	claimTTLText := os.Getenv("DEVICE_CLAIM_TTL_SECONDS")
	claimMaximumText := os.Getenv("DEVICE_CLAIM_MAX_PENDING")
	databaseURL := os.Getenv("OWNERSHIP_DATABASE_URL")
	databaseMaxText := os.Getenv("OWNERSHIP_DATABASE_MAX_CONNECTIONS")
	databaseIdleText := os.Getenv("OWNERSHIP_DATABASE_IDLE_CONNECTIONS")
	databaseTTLText := os.Getenv("OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS")
	databaseLimitText := os.Getenv("OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS")
	actionConsentMaximumText := os.Getenv("ACTION_CONSENT_MAX_PENDING")
	actionConsentPushWorkerID := os.Getenv("ACTION_CONSENT_PUSH_WORKER_ID")
	actionConsentPushPollText := os.Getenv("ACTION_CONSENT_PUSH_POLL_MS")
	actionConsentPushLeaseText := os.Getenv("ACTION_CONSENT_PUSH_LEASE_MS")
	actionConsentPushRetryText := os.Getenv("ACTION_CONSENT_PUSH_RETRY_MS")
	actionConsentPushTimeoutText := os.Getenv("ACTION_CONSENT_PUSH_REQUEST_TIMEOUT_MS")
	settings.ActionConsentEnabled, err = parseBool(
		"ACTION_CONSENT_ENABLED", false)
	if err != nil {
		return Settings{}, err
	}
	settings.ActionConsentReference, err = parseBool(
		"ACTION_CONSENT_REFERENCE_ENABLED", false)
	if err != nil {
		return Settings{}, err
	}
	if settings.ActionConsentReference {
		settings.ActionConsentEnabled = true
	}
	settings.ActionConsentPushEnabled, err = parseBool(
		"ACTION_CONSENT_PUSH_ENABLED", false)
	if err != nil {
		return Settings{}, err
	}
	pushRequested := settings.ActionConsentPushEnabled ||
		actionConsentPushWorkerID != "" || actionConsentPushPollText != "" ||
		actionConsentPushLeaseText != "" || actionConsentPushRetryText != ""
	pushRequested = pushRequested || actionConsentPushTimeoutText != ""
	if pushRequested && !settings.ActionConsentPushEnabled {
		return Settings{}, fmt.Errorf("action consent push settings require ACTION_CONSENT_PUSH_ENABLED=true")
	}
	claimRequested := appKeyText != "" || appEd25519Text != "" ||
		appIssuerText != "" || appTTLText != "" ||
		appIntrospectionURL != "" || appIntrospectionCA != "" ||
		appIntrospectionCert != "" || appIntrospectionKey != "" ||
		appIntrospectionTimeout != "" ||
		entitlementAuthorizationURL != "" ||
		claimTTLText != "" || claimMaximumText != "" || databaseURL != "" ||
		databaseMaxText != "" || databaseIdleText != "" ||
		databaseTTLText != "" || databaseLimitText != "" ||
		settings.ActionConsentEnabled || actionConsentMaximumText != "" ||
		pushRequested
	if claimRequested {
		if (appKeyText == "") == (appEd25519Text == "") {
			return Settings{}, fmt.Errorf("exactly one Companion token keyring is required for device claim")
		}
		if databaseURL == "" && !settings.AllowInsecure {
			return Settings{}, fmt.Errorf("reference device claim store is development-only; production requires a durable transactional adapter")
		}
		if databaseURL != "" {
			if err := validateOwnershipDatabaseURL(databaseURL,
				settings.AllowInsecure); err != nil {
				return Settings{}, err
			}
			databaseMax, databaseErr := parseInt(
				"OWNERSHIP_DATABASE_MAX_CONNECTIONS", 20, 2, 200)
			if databaseErr != nil {
				return Settings{}, databaseErr
			}
			databaseIdle, databaseErr := parseInt(
				"OWNERSHIP_DATABASE_IDLE_CONNECTIONS", 5, 0, databaseMax)
			if databaseErr != nil {
				return Settings{}, databaseErr
			}
			databaseTTL, databaseErr := parseInt(
				"OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS", 300, 30, 3600)
			if databaseErr != nil {
				return Settings{}, databaseErr
			}
			databaseLimit, databaseErr := parseInt(
				"OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS", 2000, 100, 30000)
			if databaseErr != nil {
				return Settings{}, databaseErr
			}
			settings.OwnershipDatabaseURL = databaseURL
			settings.OwnershipDatabaseMax = databaseMax
			settings.OwnershipDatabaseIdle = databaseIdle
			settings.OwnershipDatabaseConnTTL = time.Duration(databaseTTL) * time.Second
			settings.OwnershipDatabaseTimeout = time.Duration(databaseLimit) * time.Millisecond
		}
		if appEd25519Text != "" {
			if !auth.ValidHTTPSIssuer(appIssuerText) {
				return Settings{}, fmt.Errorf("APP_TOKEN_ISSUER must be an absolute HTTPS issuer")
			}
			settings.AppTokenEd25519Keys, err = decodeEd25519Keyring(
				"APP_TOKEN_ED25519_KEYRING", appEd25519Text)
			if err != nil {
				return Settings{}, err
			}
			settings.AppTokenIssuer = appIssuerText
		} else {
			if appIssuerText != "" {
				return Settings{}, fmt.Errorf("APP_TOKEN_ISSUER requires the Ed25519 keyring")
			}
			if !settings.AllowInsecure {
				return Settings{}, fmt.Errorf("production Companion tokens require an Ed25519 public keyring")
			}
			settings.AppTokenKeys, err = decodeKeyring(
				"APP_TOKEN_HMAC_KEYS_B64", appKeyText)
			if err != nil {
				return Settings{}, err
			}
		}
		introspectionParts := 0
		for _, value := range []string{
			appIntrospectionURL, appIntrospectionCA,
			appIntrospectionCert, appIntrospectionKey,
		} {
			if value != "" {
				introspectionParts++
			}
		}
		if introspectionParts != 0 && introspectionParts != 4 {
			return Settings{}, fmt.Errorf("Companion introspection URL, CA, client certificate, and client key must be configured together")
		}
		if appIntrospectionTimeout != "" && introspectionParts == 0 {
			return Settings{}, fmt.Errorf("APP_TOKEN_INTROSPECTION_TIMEOUT_MS requires Companion introspection")
		}
		if introspectionParts == 4 {
			if !auth.ValidCompanionIntrospectionURL(appIntrospectionURL) {
				return Settings{}, fmt.Errorf("APP_TOKEN_INTROSPECTION_URL must be the absolute HTTPS Companion introspection endpoint")
			}
			introspectionLimit, introspectionErr := parseInt(
				"APP_TOKEN_INTROSPECTION_TIMEOUT_MS", 1000, 100, 2000)
			if introspectionErr != nil {
				return Settings{}, introspectionErr
			}
			settings.AppTokenIntrospectionURL = appIntrospectionURL
			settings.AppTokenIntrospectionCA = appIntrospectionCA
			settings.AppTokenIntrospectionCert = appIntrospectionCert
			settings.AppTokenIntrospectionKey = appIntrospectionKey
			settings.AppTokenIntrospectionTimeout =
				time.Duration(introspectionLimit) * time.Millisecond
		}
		if entitlementAuthorizationURL != "" {
			if introspectionParts != 4 ||
				!accountauth.ValidServiceEntitlementAuthorizationURL(
					entitlementAuthorizationURL) ||
				!sameHTTPSAuthority(appIntrospectionURL,
					entitlementAuthorizationURL) {
				return Settings{}, fmt.Errorf("service entitlement authorization must use the Companion mTLS authority")
			}
			settings.ServiceEntitlementAuthorizationURL =
				entitlementAuthorizationURL
		}
		appTTL, ttlErr := parseInt("APP_TOKEN_MAX_TTL_SECONDS", 900, 60, 3600)
		if ttlErr != nil {
			return Settings{}, ttlErr
		}
		claimTTL, claimErr := parseInt("DEVICE_CLAIM_TTL_SECONDS", 300, 60, 600)
		if claimErr != nil {
			return Settings{}, claimErr
		}
		claimMaximum, maximumErr := parseInt(
			"DEVICE_CLAIM_MAX_PENDING", 4096, 1, 100000)
		if maximumErr != nil {
			return Settings{}, maximumErr
		}
		settings.DeviceClaimEnabled = true
		settings.AppTokenMaxTTL = time.Duration(appTTL) * time.Second
		settings.DeviceClaimTTL = time.Duration(claimTTL) * time.Second
		settings.DeviceClaimMaxPending = claimMaximum
		if settings.ActionConsentReference && !settings.AllowInsecure {
			return Settings{}, fmt.Errorf("reference action consent store is development-only; production requires a durable multi-replica adapter")
		}
		if settings.ActionConsentReference && databaseURL != "" {
			return Settings{}, fmt.Errorf("reference action consent store cannot be combined with PostgreSQL")
		}
		if actionConsentMaximumText != "" &&
			!settings.ActionConsentEnabled {
			return Settings{}, fmt.Errorf("ACTION_CONSENT_MAX_PENDING requires ACTION_CONSENT_ENABLED")
		}
		if settings.ActionConsentEnabled {
			if !settings.ActionConsentReference && databaseURL == "" {
				return Settings{}, fmt.Errorf("durable action consent requires OWNERSHIP_DATABASE_URL")
			}
			actionMaximum, actionErr := parseInt(
				"ACTION_CONSENT_MAX_PENDING", 4096, 1, 100000)
			if actionErr != nil {
				return Settings{}, actionErr
			}
			settings.ActionConsentMaxPending = actionMaximum
		}
		if settings.ActionConsentPushEnabled {
			if !settings.ActionConsentEnabled || settings.ActionConsentReference ||
				databaseURL == "" {
				return Settings{}, fmt.Errorf("action consent push requires the durable PostgreSQL consent store")
			}
			if settings.AppTokenIntrospectionURL == "" {
				return Settings{}, fmt.Errorf("action consent push requires the existing Companion mTLS service boundary")
			}
			if !auth.ValidIdentifier(actionConsentPushWorkerID, 64) {
				return Settings{}, fmt.Errorf("invalid ACTION_CONSENT_PUSH_WORKER_ID")
			}
			poll, pushErr := parseInt(
				"ACTION_CONSENT_PUSH_POLL_MS", 500, 100, 5000)
			if pushErr != nil {
				return Settings{}, pushErr
			}
			lease, pushErr := parseInt(
				"ACTION_CONSENT_PUSH_LEASE_MS", 9000, 100, 10000)
			if pushErr != nil {
				return Settings{}, pushErr
			}
			retry, pushErr := parseInt(
				"ACTION_CONSENT_PUSH_RETRY_MS", 1000, 0, 5000)
			if pushErr != nil {
				return Settings{}, pushErr
			}
			requestTimeout, pushErr := parseInt(
				"ACTION_CONSENT_PUSH_REQUEST_TIMEOUT_MS", 7000, 500, 8000)
			if pushErr != nil {
				return Settings{}, pushErr
			}
			if lease <= requestTimeout {
				return Settings{}, fmt.Errorf("action consent wake lease must exceed the private request timeout")
			}
			settings.ActionConsentPushWorkerID = actionConsentPushWorkerID
			settings.ActionConsentPushPoll = time.Duration(poll) * time.Millisecond
			settings.ActionConsentPushLease = time.Duration(lease) * time.Millisecond
			settings.ActionConsentPushRetry = time.Duration(retry) * time.Millisecond
			settings.ActionConsentPushTimeout =
				time.Duration(requestTimeout) * time.Millisecond
		}
		if !settings.AllowInsecure && settings.AppTokenIntrospectionURL == "" {
			return Settings{}, fmt.Errorf("production Companion authorization requires online mTLS token introspection")
		}
		if !settings.AllowInsecure &&
			settings.ServiceEntitlementAuthorizationURL == "" {
			return Settings{}, fmt.Errorf("production token issuance requires service entitlement authorization")
		}
		keyIsolation := false
		if settings.VoiceTokenKeyring != nil {
			keyIsolation = auth.ManagedTokenKeyringsDisjointFromSecrets(
				[]*auth.ManagedTokenKeyring{settings.VoiceTokenKeyring,
					settings.AgentTokenKeyring}, settings.AppTokenKeys)
		} else {
			keys := append([][]byte{settings.VoiceTokenKey,
				settings.AgentTokenKey}, settings.AppTokenKeys...)
			keyIsolation = distinctKeys(keys)
		}
		if !keyIsolation {
			return Settings{}, fmt.Errorf("voice, Agent, and App token keys must be distinct")
		}
	}
	settings.OTAReleaseRegistryFile = os.Getenv("OTA_RELEASE_REGISTRY_FILE")
	otaTokenText := os.Getenv("OTA_TOKEN_HMAC_KEY_B64")
	otaKeyringFile := os.Getenv("OTA_TOKEN_HMAC_KEYRING_FILE")
	otaKeyringFloor := os.Getenv("OTA_TOKEN_HMAC_KEYRING_MIN_REVISION")
	otaRolloutText := os.Getenv("OTA_ROLLOUT_HMAC_KEY_B64")
	otaTTLText := os.Getenv("OTA_TOKEN_TTL_SECONDS")
	otaRequested := settings.OTAReleaseRegistryFile != "" || otaTokenText != "" ||
		otaKeyringFile != "" || otaKeyringFloor != "" ||
		otaRolloutText != "" || otaTTLText != ""
	generationRequested := os.Getenv("GENERATION_COORDINATOR_URL") != "" ||
		os.Getenv("GENERATION_REPLICA_ID") != "" ||
		os.Getenv("GENERATION_REPLICA_HMAC_KEY_B64") != "" ||
		os.Getenv("OTA_DEPLOYMENT_BUNDLE_ROOT") != ""
	if generationRequested && !otaRequested {
		return Settings{}, fmt.Errorf("generation guard settings require OTA")
	}
	if otaRequested {
		if settings.OTAReleaseRegistryFile == "" || otaRolloutText == "" {
			return Settings{}, fmt.Errorf("OTA release registry, token keyring, and rollout key must be configured together")
		}
		settings.OTATokenKeyring, settings.OTATokenKey, err =
			loadIssuanceTokenKeyring("OTA", "OTA_TOKEN_HMAC_KEYRING_FILE",
				"OTA_TOKEN_HMAC_KEYRING_MIN_REVISION",
				"OTA_TOKEN_HMAC_KEY_B64", settings.AllowInsecure)
		if err != nil {
			return Settings{}, err
		}
		if (settings.VoiceTokenKeyring == nil) !=
			(settings.OTATokenKeyring == nil) {
			return Settings{}, fmt.Errorf("voice, Agent, and OTA token keyrings must use the same managed mode")
		}
		settings.OTARolloutKey, err = decodeKey("OTA_ROLLOUT_HMAC_KEY_B64", otaRolloutText)
		if err != nil {
			return Settings{}, err
		}
		keyIsolation := false
		var legacyKeys [][]byte
		if settings.VoiceTokenKeyring != nil {
			otherSecrets := append([][]byte{settings.OTARolloutKey},
				settings.AppTokenKeys...)
			keyIsolation = auth.ManagedTokenKeyringsDisjointFromSecrets(
				[]*auth.ManagedTokenKeyring{settings.VoiceTokenKeyring,
					settings.AgentTokenKeyring, settings.OTATokenKeyring},
				otherSecrets)
		} else {
			legacyKeys = append([][]byte{settings.VoiceTokenKey,
				settings.AgentTokenKey, settings.OTATokenKey,
				settings.OTARolloutKey}, settings.AppTokenKeys...)
			keyIsolation = distinctKeys(legacyKeys)
		}
		if !keyIsolation {
			return Settings{}, fmt.Errorf("voice, Agent, App, OTA token, and rollout keys must be distinct")
		}
		otaTTL, ttlErr := parseInt("OTA_TOKEN_TTL_SECONDS", 300, 60, 900)
		if ttlErr != nil {
			return Settings{}, ttlErr
		}
		settings.OTATokenTTL = time.Duration(otaTTL) * time.Second
		settings.Generation, err = generation.LoadReplicaSettings(
			"controlplane", settings.AllowInsecure)
		if err != nil {
			return Settings{}, err
		}
		generationIsolated := true
		if settings.VoiceTokenKeyring != nil {
			generationIsolated = auth.ManagedTokenKeyringsDisjointFromSecrets(
				[]*auth.ManagedTokenKeyring{settings.VoiceTokenKeyring,
					settings.AgentTokenKeyring, settings.OTATokenKeyring},
				append([][]byte{settings.OTARolloutKey,
					settings.Generation.Replica.Key}, settings.AppTokenKeys...))
		} else {
			for _, key := range legacyKeys {
				if len(key) == len(settings.Generation.Replica.Key) &&
					subtle.ConstantTimeCompare(key, settings.Generation.Replica.Key) == 1 {
					generationIsolated = false
				}
			}
		}
		if !generationIsolated {
			return Settings{}, fmt.Errorf("generation replica key must be isolated from service keys")
		}
	}
	voiceTTL, err := parseInt("VOICE_TOKEN_TTL_SECONDS", 900, 60, 3600)
	if err != nil {
		return Settings{}, err
	}
	agentTTL, err := parseInt("AGENT_TOKEN_TTL_SECONDS", 600, 60, 3600)
	if err != nil {
		return Settings{}, err
	}
	proofSkew, err := parseInt("DEVICE_PROOF_MAX_SKEW_SECONDS", 60, 10, 300)
	if err != nil {
		return Settings{}, err
	}
	proofInterval, err := parseInt("DEVICE_PROOF_MIN_INTERVAL_SECONDS", 5, 0, 60)
	if err != nil {
		return Settings{}, err
	}
	settings.VoiceTokenTTL = time.Duration(voiceTTL) * time.Second
	settings.AgentTokenTTL = time.Duration(agentTTL) * time.Second
	settings.ProofMaxSkew = time.Duration(proofSkew) * time.Second
	settings.ProofMinInterval = time.Duration(proofInterval) * time.Second
	return settings, nil
}

func loadIssuanceTokenKeyring(label, fileEnvironment, floorEnvironment,
	legacyEnvironment string, allowInsecure bool) (*auth.ManagedTokenKeyring,
	[]byte, error) {
	file := strings.TrimSpace(os.Getenv(fileEnvironment))
	floor := strings.TrimSpace(os.Getenv(floorEnvironment))
	legacy := strings.TrimSpace(os.Getenv(legacyEnvironment))
	if file != "" || floor != "" {
		if file == "" || floor == "" || legacy != "" {
			return nil, nil, fmt.Errorf("%s managed token keyring file/revision must be configured together without legacy key", label)
		}
		minimumRevision, err := strconv.ParseUint(floor, 10, 64)
		if err != nil || minimumRevision == 0 ||
			strconv.FormatUint(minimumRevision, 10) != floor {
			return nil, nil, fmt.Errorf("%s managed token keyring revision is invalid", label)
		}
		keyring, err := auth.LoadManagedTokenKeyring(
			file, minimumRevision, time.Now().UTC())
		if err != nil {
			return nil, nil, err
		}
		return keyring, nil, nil
	}
	if !allowInsecure {
		return nil, nil, fmt.Errorf("production control plane requires a managed %s token keyring", label)
	}
	key, err := decodeKey(legacyEnvironment, legacy)
	if err != nil {
		return nil, nil, err
	}
	return nil, key, nil
}

func decodeKeyring(name, value string) ([][]byte, error) {
	parts := strings.Split(value, ",")
	if value == "" || len(parts) == 0 || len(parts) > 3 {
		return nil, fmt.Errorf("%s must contain 1 through 3 keys", name)
	}
	keys := make([][]byte, 0, len(parts))
	for _, part := range parts {
		key, err := decodeKey(name, strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if !distinctKeys(keys) {
		return nil, fmt.Errorf("%s keys must be distinct", name)
	}
	return keys, nil
}

func decodeEd25519Keyring(name, value string) (
	map[string]ed25519.PublicKey, error) {
	parts := strings.Split(value, ",")
	if value == "" || len(parts) == 0 || len(parts) > 3 {
		return nil, fmt.Errorf("%s must contain 1 through 3 keys", name)
	}
	keys := make(map[string]ed25519.PublicKey, len(parts))
	for _, part := range parts {
		fields := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(fields) != 2 || !auth.ValidIdentifier(fields[0], 64) {
			return nil, fmt.Errorf("%s entry is invalid", name)
		}
		if _, duplicate := keys[fields[0]]; duplicate {
			return nil, fmt.Errorf("%s key ids must be distinct", name)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(fields[1])
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(decoded) != fields[1] {
			return nil, fmt.Errorf(
				"%s keys must be canonical Ed25519 public keys", name)
		}
		keys[fields[0]] = append(ed25519.PublicKey(nil), decoded...)
	}
	return keys, nil
}

func distinctKeys(keys [][]byte) bool {
	for left := range keys {
		for right := left + 1; right < len(keys); right++ {
			if len(keys[left]) == len(keys[right]) &&
				subtle.ConstantTimeCompare(keys[left], keys[right]) == 1 {
				return false
			}
		}
	}
	return true
}

func decodeKey(name, value string) ([]byte, error) {
	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, err = encoding.DecodeString(value); err == nil {
			break
		}
	}
	if err != nil || len(decoded) < 32 || len(decoded) > 128 {
		return nil, fmt.Errorf("%s must encode 32 through 128 bytes", name)
	}
	return decoded, nil
}

func validatePublicWSS(value string, allowInsecure bool) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" || endpoint.Path != "/v1/device" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("PUBLIC_DEVICE_WSS_URL must be an absolute WebSocket /v1/device URL")
	}
	if endpoint.Scheme != "wss" && !(allowInsecure && endpoint.Scheme == "ws") {
		return fmt.Errorf("PUBLIC_DEVICE_WSS_URL must use wss outside development mode")
	}
	return nil
}

func sameHTTPSAuthority(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	return leftErr == nil && rightErr == nil && leftURL.Scheme == "https" &&
		rightURL.Scheme == "https" && leftURL.Host == rightURL.Host
}

func validateOwnershipDatabaseURL(value string, allowInsecure bool) error {
	endpoint, err := url.Parse(value)
	if err != nil || (endpoint.Scheme != "postgres" &&
		endpoint.Scheme != "postgresql") || endpoint.Host == "" ||
		endpoint.Path == "" || endpoint.Path == "/" || endpoint.Fragment != "" {
		return fmt.Errorf("OWNERSHIP_DATABASE_URL must be an absolute PostgreSQL database URL")
	}
	sslModes := endpoint.Query()["sslmode"]
	if len(sslModes) > 1 {
		return fmt.Errorf("OWNERSHIP_DATABASE_URL must contain at most one sslmode")
	}
	if !allowInsecure && (len(sslModes) != 1 || sslModes[0] != "verify-full") {
		return fmt.Errorf("OWNERSHIP_DATABASE_URL must use sslmode=verify-full outside development")
	}
	return nil
}

func parseBool(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func parseInt(name string, fallback, minimum, maximum int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d",
			name, minimum, maximum)
	}
	return parsed, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
