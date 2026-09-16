package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ManagedTokenKeyringSchema    = "xz-hmac-token-keyring-v1"
	maximumManagedKeyringBytes   = 32 * 1024
	maximumManagedTokenKeyLength = 128
	maximumManagedTokenKeys      = 3
)

type managedKeyringDocument struct {
	Schema                       string                        `json:"schema"`
	Revision                     uint64                        `json:"revision"`
	ActiveKeyID                  string                        `json:"active_key_id"`
	LegacyUnkeyedKeyID           string                        `json:"legacy_unkeyed_key_id"`
	LegacyUnkeyedVerifyUntilUnix int64                         `json:"legacy_unkeyed_verify_until_unix"`
	Keys                         []managedKeyringDocumentEntry `json:"keys"`
}

type managedKeyringDocumentEntry struct {
	KeyID           string `json:"key_id"`
	HMACKeyB64URL   string `json:"hmac_key_b64url"`
	State           string `json:"state"`
	IssueBeforeUnix int64  `json:"issue_before_unix"`
	VerifyUntilUnix int64  `json:"verify_until_unix"`
}

type managedTokenKey struct {
	id          string
	secret      []byte
	state       string
	issueBefore time.Time
	verifyUntil time.Time
}

// ManagedTokenKeyring is an immutable issuance/verification snapshot. It
// exposes only non-secret metadata; raw key material remains private to auth.
type ManagedTokenKeyring struct {
	revision           uint64
	activeKeyID        string
	legacyUnkeyedKeyID string
	legacyVerifyUntil  time.Time
	keys               map[string]managedTokenKey
}

func (keyring *ManagedTokenKeyring) Revision() uint64 {
	if keyring == nil {
		return 0
	}
	return keyring.revision
}

func (keyring *ManagedTokenKeyring) ActiveKeyID() string {
	if keyring == nil {
		return ""
	}
	return keyring.activeKeyID
}

// LoadManagedTokenKeyring reads a canonical, private, bounded keyring file.
// minimumRevision is an externally approved rollback floor.
func LoadManagedTokenKeyring(path string, minimumRevision uint64,
	now time.Time) (*ManagedTokenKeyring, error) {
	if path == "" || minimumRevision == 0 || now.IsZero() {
		return nil, fmt.Errorf("managed token keyring configuration is invalid")
	}
	status, err := os.Stat(path)
	if err != nil || !status.Mode().IsRegular() || status.Size() < 1 ||
		status.Size() > maximumManagedKeyringBytes || status.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("managed token keyring must be a private bounded regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil || int64(len(payload)) != status.Size() {
		return nil, fmt.Errorf("cannot read managed token keyring")
	}
	defer clearManagedBytes(payload)
	if strictjson.RejectDuplicateFields(payload) != nil {
		return nil, fmt.Errorf("managed token keyring JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document managedKeyringDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("managed token keyring JSON is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("managed token keyring JSON has trailing data")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, fmt.Errorf("managed token keyring JSON is not canonical")
	}
	return buildManagedTokenKeyring(document, minimumRevision, now.UTC())
}

func buildManagedTokenKeyring(document managedKeyringDocument,
	minimumRevision uint64, now time.Time) (*ManagedTokenKeyring, error) {
	if document.Schema != ManagedTokenKeyringSchema ||
		document.Revision < minimumRevision || document.Revision == 0 ||
		!ValidIdentifier(document.ActiveKeyID, 64) || len(document.Keys) < 1 ||
		len(document.Keys) > maximumManagedTokenKeys {
		return nil, fmt.Errorf("managed token keyring identity is invalid")
	}
	legacyConfigured := document.LegacyUnkeyedKeyID != "" ||
		document.LegacyUnkeyedVerifyUntilUnix != 0
	if legacyConfigured && (!ValidIdentifier(document.LegacyUnkeyedKeyID, 64) ||
		!validManagedTime(document.LegacyUnkeyedVerifyUntilUnix)) {
		return nil, fmt.Errorf("managed token legacy transition is invalid")
	}
	keyring := &ManagedTokenKeyring{
		revision: document.Revision, activeKeyID: document.ActiveKeyID,
		legacyUnkeyedKeyID: document.LegacyUnkeyedKeyID,
		keys:               make(map[string]managedTokenKey, len(document.Keys)),
	}
	if legacyConfigured {
		keyring.legacyVerifyUntil = time.Unix(
			document.LegacyUnkeyedVerifyUntilUnix, 0).UTC()
	}
	seenMaterial := make([][]byte, 0, len(document.Keys))
	previousID := ""
	activeCount := 0
	for _, entry := range document.Keys {
		if !ValidIdentifier(entry.KeyID, 64) ||
			(previousID != "" && entry.KeyID <= previousID) ||
			!validManagedTime(entry.VerifyUntilUnix) {
			return nil, fmt.Errorf("managed token key entry is invalid")
		}
		secret, decodeErr := base64.RawURLEncoding.Strict().DecodeString(
			entry.HMACKeyB64URL)
		if decodeErr != nil || len(secret) < 32 ||
			len(secret) > maximumManagedTokenKeyLength ||
			base64.RawURLEncoding.EncodeToString(secret) != entry.HMACKeyB64URL {
			clearManagedBytes(secret)
			return nil, fmt.Errorf("managed token key material is invalid")
		}
		for _, prior := range seenMaterial {
			if len(prior) == len(secret) &&
				subtle.ConstantTimeCompare(prior, secret) == 1 {
				clearManagedBytes(secret)
				return nil, fmt.Errorf("managed token key material must be distinct")
			}
		}
		verifyUntil := time.Unix(entry.VerifyUntilUnix, 0).UTC()
		key := managedTokenKey{id: entry.KeyID, secret: secret,
			state: entry.State, verifyUntil: verifyUntil}
		switch entry.State {
		case "active":
			if entry.KeyID != document.ActiveKeyID || entry.IssueBeforeUnix != 0 ||
				!verifyUntil.After(now) {
				clearManagedBytes(secret)
				return nil, fmt.Errorf("managed active token key is invalid")
			}
			activeCount++
		case "retiring":
			if entry.KeyID == document.ActiveKeyID ||
				!validManagedTime(entry.IssueBeforeUnix) ||
				entry.VerifyUntilUnix <= entry.IssueBeforeUnix ||
				!verifyUntil.After(now) {
				clearManagedBytes(secret)
				return nil, fmt.Errorf("managed retiring token key is invalid")
			}
			key.issueBefore = time.Unix(entry.IssueBeforeUnix, 0).UTC()
		default:
			clearManagedBytes(secret)
			return nil, fmt.Errorf("managed token key state is invalid")
		}
		keyring.keys[entry.KeyID] = key
		seenMaterial = append(seenMaterial, secret)
		previousID = entry.KeyID
	}
	if activeCount != 1 {
		return nil, fmt.Errorf("managed token keyring must contain one active key")
	}
	if legacyConfigured {
		legacy, found := keyring.keys[keyring.legacyUnkeyedKeyID]
		if !found || legacy.state != "retiring" ||
			keyring.legacyVerifyUntil.After(legacy.verifyUntil) ||
			!keyring.legacyVerifyUntil.After(now) {
			return nil, fmt.Errorf("managed token legacy transition is invalid")
		}
	}
	return keyring, nil
}

func validManagedTime(value int64) bool {
	minimum := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	maximum := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	return value >= minimum && value < maximum
}

func clearManagedBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// ManagedTokenKeyringsDisjoint verifies domain separation across every active
// and retiring key, not only the current issuers.
func ManagedTokenKeyringsDisjoint(keyrings ...*ManagedTokenKeyring) bool {
	return ManagedTokenKeyringsDisjointFromSecrets(keyrings, nil)
}

func ManagedTokenKeyringsDisjointFromSecrets(keyrings []*ManagedTokenKeyring,
	secrets [][]byte) bool {
	var materials [][]byte
	for _, keyring := range keyrings {
		if keyring == nil || len(keyring.keys) == 0 {
			return false
		}
		ids := make([]string, 0, len(keyring.keys))
		for id := range keyring.keys {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			secret := keyring.keys[id].secret
			for _, prior := range materials {
				if len(prior) == len(secret) &&
					subtle.ConstantTimeCompare(prior, secret) == 1 {
					return false
				}
			}
			materials = append(materials, secret)
		}
	}
	for _, secret := range secrets {
		if len(secret) < 32 {
			return false
		}
		for _, prior := range materials {
			if len(prior) == len(secret) &&
				subtle.ConstantTimeCompare(prior, secret) == 1 {
				return false
			}
		}
		materials = append(materials, secret)
	}
	return true
}
