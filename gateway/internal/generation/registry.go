package generation

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type ReplicaIdentity struct {
	ReplicaID  string `json:"replica_id"`
	Role       string `json:"role"`
	HMACKeyB64 string `json:"hmac_key_b64"`
}

type replicaRegistryDocument struct {
	Version  int               `json:"version"`
	Replicas []ReplicaIdentity `json:"replicas"`
}

type ReplicaRegistry struct {
	identities map[string]Principal
	references []ReplicaRef
}

type Principal struct {
	ID   string
	Role string
	Key  []byte
}

func LoadReplicaRegistry(name string) (*ReplicaRegistry, error) {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("generation replica registry must be a private regular file")
	}
	payload, err := readBoundedRegular(name, maximumStateBytes)
	if err != nil {
		return nil, fmt.Errorf("read generation replica registry: %w", err)
	}
	var document replicaRegistryDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || ensureJSONEOF(decoder) != nil {
		return nil, fmt.Errorf("decode generation replica registry")
	}
	canonical, _ := json.Marshal(document)
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, payload) || document.Version != 1 ||
		len(document.Replicas) < 2 || len(document.Replicas) > 64 {
		return nil, fmt.Errorf("generation replica registry is not canonical")
	}
	result := &ReplicaRegistry{
		identities: make(map[string]Principal, len(document.Replicas)),
		references: make([]ReplicaRef, 0, len(document.Replicas)),
	}
	seenKeys := make([][]byte, 0, len(document.Replicas))
	priorID := ""
	for _, entry := range document.Replicas {
		if !auth.ValidIdentifier(entry.ReplicaID, 64) ||
			(entry.Role != "controlplane" && entry.Role != "firmwareorigin") {
			return nil, fmt.Errorf("generation replica registry entry is invalid")
		}
		if entry.ReplicaID <= priorID {
			return nil, fmt.Errorf("generation replica registry is not uniquely sorted")
		}
		priorID = entry.ReplicaID
		if _, exists := result.identities[entry.ReplicaID]; exists {
			return nil, fmt.Errorf("generation replica ID is duplicated")
		}
		key, err := decodeCanonicalKey(entry.HMACKeyB64)
		if err != nil {
			return nil, fmt.Errorf("generation replica key is invalid")
		}
		for _, prior := range seenKeys {
			if len(prior) == len(key) && subtle.ConstantTimeCompare(prior, key) == 1 {
				return nil, fmt.Errorf("generation replica keys must be distinct")
			}
		}
		seenKeys = append(seenKeys, key)
		result.identities[entry.ReplicaID] = Principal{
			ID: entry.ReplicaID, Role: entry.Role, Key: key,
		}
		result.references = append(result.references, ReplicaRef{
			ID: entry.ReplicaID, Role: entry.Role,
		})
	}
	sortReplicas(result.references)
	if !validReplicas(result.references) {
		return nil, fmt.Errorf("generation replica registry requires both service roles")
	}
	return result, nil
}

func (registry *ReplicaRegistry) References() []ReplicaRef {
	return append([]ReplicaRef(nil), registry.references...)
}

func (registry *ReplicaRegistry) Principal(id string) (Principal, bool) {
	principal, found := registry.identities[id]
	principal.Key = append([]byte(nil), principal.Key...)
	return principal, found
}

func (registry *ReplicaRegistry) DistinctFrom(keys ...[]byte) bool {
	for _, principal := range registry.identities {
		for _, key := range keys {
			if len(principal.Key) == len(key) &&
				subtle.ConstantTimeCompare(principal.Key, key) == 1 {
				return false
			}
		}
	}
	return true
}

func DecodeHMACKey(name, value string) ([]byte, error) {
	key, err := decodeCanonicalKey(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url for 32 through 128 bytes", name)
	}
	return key, nil
}

func decodeCanonicalKey(value string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(key) < 32 || len(key) > 128 ||
		base64.RawURLEncoding.EncodeToString(key) != value {
		return nil, fmt.Errorf("invalid key")
	}
	return key, nil
}
