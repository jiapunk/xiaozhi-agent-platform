package accountauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ServiceEntitlementUpdateKeyringSchema = "xz-service-entitlement-update-keyring-v1"
	maximumEntitlementUpdateKeyringBytes  = 16 * 1024
	maximumEntitlementUpdateKeys          = 3
)

type entitlementUpdateKeyringDocument struct {
	Schema   string                                `json:"schema"`
	Revision uint64                                `json:"revision"`
	Keys     []entitlementUpdateKeyringDocumentKey `json:"keys"`
}

type entitlementUpdateKeyringDocumentKey struct {
	KeyID              string `json:"key_id"`
	PublicKeyBase64URL string `json:"public_key_base64url"`
	State              string `json:"state"`
	VerifyUntilUnix    int64  `json:"verify_until_unix"`
}

type entitlementUpdateVerificationKey struct {
	publicKey   ed25519.PublicKey
	state       string
	verifyUntil time.Time
}

// EntitlementUpdateKeyring is an immutable trust snapshot for normalized
// billing/IdP adapter events. It contains public verification keys only, but
// the file is still private because changing it changes who may mutate the
// commercial entitlement ledger.
type EntitlementUpdateKeyring struct {
	revision uint64
	keys     map[string]entitlementUpdateVerificationKey
}

func (keyring *EntitlementUpdateKeyring) Revision() uint64 {
	if keyring == nil {
		return 0
	}
	return keyring.revision
}

// LoadEntitlementUpdateKeyring reads a canonical, rollback-fenced, bounded
// regular file. A symlink or group/world-accessible trust file is rejected.
func LoadEntitlementUpdateKeyring(path string, minimumRevision uint64,
	now time.Time) (*EntitlementUpdateKeyring, error) {
	if path == "" || minimumRevision == 0 || now.IsZero() {
		return nil, fmt.Errorf("entitlement update keyring configuration is invalid")
	}
	linkStatus, err := os.Lstat(path)
	if err != nil || linkStatus.Mode()&os.ModeSymlink != 0 ||
		!linkStatus.Mode().IsRegular() || linkStatus.Size() < 1 ||
		linkStatus.Size() > maximumEntitlementUpdateKeyringBytes ||
		linkStatus.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("entitlement update keyring must be a private bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read entitlement update keyring")
	}
	defer file.Close()
	openedStatus, err := file.Stat()
	if err != nil || !os.SameFile(linkStatus, openedStatus) ||
		!openedStatus.Mode().IsRegular() ||
		openedStatus.Mode().Perm()&0o077 != 0 ||
		openedStatus.Size() != linkStatus.Size() {
		return nil, fmt.Errorf("entitlement update keyring changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file,
		maximumEntitlementUpdateKeyringBytes+1))
	if err != nil || int64(len(payload)) != openedStatus.Size() ||
		len(payload) > maximumEntitlementUpdateKeyringBytes {
		return nil, fmt.Errorf("cannot read entitlement update keyring")
	}
	defer clearBytes(payload)
	if strictjson.RejectDuplicateFields(payload) != nil {
		return nil, fmt.Errorf("entitlement update keyring JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document entitlementUpdateKeyringDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("entitlement update keyring JSON is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("entitlement update keyring JSON has trailing data")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, fmt.Errorf("entitlement update keyring JSON is not canonical")
	}
	return buildEntitlementUpdateKeyring(document, minimumRevision, now.UTC())
}

func buildEntitlementUpdateKeyring(document entitlementUpdateKeyringDocument,
	minimumRevision uint64, now time.Time) (*EntitlementUpdateKeyring, error) {
	if document.Schema != ServiceEntitlementUpdateKeyringSchema ||
		document.Revision < minimumRevision || document.Revision == 0 ||
		len(document.Keys) < 1 ||
		len(document.Keys) > maximumEntitlementUpdateKeys {
		return nil, fmt.Errorf("entitlement update keyring identity is invalid")
	}
	keyring := &EntitlementUpdateKeyring{revision: document.Revision,
		keys: make(map[string]entitlementUpdateVerificationKey,
			len(document.Keys))}
	previousID := ""
	activeCount := 0
	seenMaterial := make([]ed25519.PublicKey, 0, len(document.Keys))
	for _, entry := range document.Keys {
		if !auth.ValidIdentifier(entry.KeyID, 64) ||
			(previousID != "" && entry.KeyID <= previousID) ||
			!validEntitlementUpdateTrustTime(entry.VerifyUntilUnix) {
			return nil, fmt.Errorf("entitlement update key entry is invalid")
		}
		publicKey, decodeErr := base64.RawURLEncoding.Strict().DecodeString(
			entry.PublicKeyBase64URL)
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(publicKey) !=
				entry.PublicKeyBase64URL {
			clearBytes(publicKey)
			return nil, fmt.Errorf("entitlement update public key is invalid")
		}
		for _, prior := range seenMaterial {
			if subtle.ConstantTimeCompare(prior, publicKey) == 1 {
				clearBytes(publicKey)
				return nil, fmt.Errorf("entitlement update public keys must be distinct")
			}
		}
		verifyUntil := time.Unix(entry.VerifyUntilUnix, 0).UTC()
		if !verifyUntil.After(now) {
			clearBytes(publicKey)
			return nil, fmt.Errorf("entitlement update verification key is expired")
		}
		switch entry.State {
		case "active":
			activeCount++
		case "retiring":
		default:
			clearBytes(publicKey)
			return nil, fmt.Errorf("entitlement update key state is invalid")
		}
		keyring.keys[entry.KeyID] = entitlementUpdateVerificationKey{
			publicKey: append(ed25519.PublicKey(nil), publicKey...),
			state:     entry.State, verifyUntil: verifyUntil}
		seenMaterial = append(seenMaterial,
			append(ed25519.PublicKey(nil), publicKey...))
		clearBytes(publicKey)
		previousID = entry.KeyID
	}
	if activeCount != 1 {
		return nil, fmt.Errorf("entitlement update keyring must contain one active key")
	}
	return keyring, nil
}

func validEntitlementUpdateTrustTime(value int64) bool {
	minimum := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	maximum := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	return value >= minimum && value < maximum
}

func (keyring *EntitlementUpdateKeyring) verify(keyID string, message,
	signature []byte, authorizationExpiresAt, now time.Time) bool {
	if keyring == nil || !auth.ValidIdentifier(keyID, 64) ||
		len(signature) != ed25519.SignatureSize || now.IsZero() ||
		authorizationExpiresAt.IsZero() {
		return false
	}
	key, found := keyring.keys[keyID]
	if !found || (key.state != "active" && key.state != "retiring") ||
		!key.verifyUntil.After(now.UTC()) ||
		authorizationExpiresAt.UTC().After(key.verifyUntil) {
		return false
	}
	return ed25519.Verify(key.publicKey, message, signature)
}
