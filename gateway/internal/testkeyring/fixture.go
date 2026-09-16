// Package testkeyring writes deterministic-shape managed token keyrings for
// configuration tests. It is not imported by serving commands.
package testkeyring

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type document struct {
	Schema                       string  `json:"schema"`
	Revision                     uint64  `json:"revision"`
	ActiveKeyID                  string  `json:"active_key_id"`
	LegacyUnkeyedKeyID           string  `json:"legacy_unkeyed_key_id"`
	LegacyUnkeyedVerifyUntilUnix int64   `json:"legacy_unkeyed_verify_until_unix"`
	Keys                         []entry `json:"keys"`
}

type entry struct {
	KeyID           string `json:"key_id"`
	HMACKeyB64URL   string `json:"hmac_key_b64url"`
	State           string `json:"state"`
	IssueBeforeUnix int64  `json:"issue_before_unix"`
	VerifyUntilUnix int64  `json:"verify_until_unix"`
}

func Write(path, prefix string, revision uint64, now time.Time) error {
	if path == "" || prefix == "" || revision == 0 || now.IsZero() {
		return fmt.Errorf("invalid test keyring fixture")
	}
	key := sha256.Sum256([]byte("XIAOZHI-TEST-MANAGED-TOKEN-KEY\x00" + prefix))
	value := document{
		Schema: "xz-hmac-token-keyring-v1", Revision: revision,
		ActiveKeyID: prefix + "-active", Keys: []entry{{
			KeyID:         prefix + "-active",
			HMACKeyB64URL: base64.RawURLEncoding.EncodeToString(key[:]),
			State:         "active", VerifyUntilUnix: now.Add(365 * 24 * time.Hour).Unix(),
		}},
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}
