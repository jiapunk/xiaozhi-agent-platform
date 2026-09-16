package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	managedOldKey  = []byte("managed-old-key-0123456789abcdef012")
	managedNewKey  = []byte("managed-new-key-0123456789abcdef012")
	managedNextKey = []byte("managed-next-key-0123456789abcdef01")
)

func managedDocument(now time.Time) managedKeyringDocument {
	return managedKeyringDocument{
		Schema: ManagedTokenKeyringSchema, Revision: 7,
		ActiveKeyID:                  "voice-2026-q4",
		LegacyUnkeyedKeyID:           "voice-2026-q3",
		LegacyUnkeyedVerifyUntilUnix: now.Add(2 * time.Hour).Unix(),
		Keys: []managedKeyringDocumentEntry{
			{KeyID: "voice-2026-q3",
				HMACKeyB64URL: base64.RawURLEncoding.EncodeToString(managedOldKey),
				State:         "retiring", IssueBeforeUnix: now.Add(time.Hour).Unix(),
				VerifyUntilUnix: now.Add(3 * time.Hour).Unix()},
			{KeyID: "voice-2026-q4",
				HMACKeyB64URL: base64.RawURLEncoding.EncodeToString(managedNewKey),
				State:         "active", VerifyUntilUnix: now.Add(24 * time.Hour).Unix()},
		},
	}
}

func writeManagedDocument(t *testing.T, document managedKeyringDocument) string {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadManagedFixture(t *testing.T, now time.Time) *ManagedTokenKeyring {
	t.Helper()
	keyring, err := LoadManagedTokenKeyring(
		writeManagedDocument(t, managedDocument(now)), 7, now)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func loadManagedDocument(t *testing.T, document managedKeyringDocument,
	minimumRevision uint64, now time.Time) *ManagedTokenKeyring {
	t.Helper()
	keyring, err := LoadManagedTokenKeyring(
		writeManagedDocument(t, document), minimumRevision, now)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func managedRotationTarget(now time.Time) managedKeyringDocument {
	document := managedDocument(now)
	document.Revision = 8
	document.ActiveKeyID = "voice-2027-q1"
	document.Keys[1].State = "retiring"
	document.Keys[1].IssueBeforeUnix = now.Add(2 * time.Hour).Unix()
	document.Keys = append(document.Keys, managedKeyringDocumentEntry{
		KeyID:         "voice-2027-q1",
		HMACKeyB64URL: base64.RawURLEncoding.EncodeToString(managedNextKey),
		State:         "active", VerifyUntilUnix: now.Add(48 * time.Hour).Unix(),
	})
	return document
}

func managedRecoveryTarget(now time.Time) managedKeyringDocument {
	document := managedRotationTarget(now)
	document.Revision = 9
	document.ActiveKeyID = "voice-2026-q4"
	document.Keys[1].State = "active"
	document.Keys[1].IssueBeforeUnix = 0
	document.Keys[1].VerifyUntilUnix = now.Add(48 * time.Hour).Unix()
	document.Keys[2].State = "retiring"
	document.Keys[2].IssueBeforeUnix = now.Add(3 * time.Hour).Unix()
	return document
}

func signManagedTestToken(t *testing.T, secret []byte, version, keyID string,
	claims Claims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	input := strings.Join([]string{version, keyID, encoded}, ".")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func managedVoiceClaims(now time.Time) Claims {
	return Claims{
		DeviceID: "device-1", OwnerID: "owner-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		Audience: VoiceAudience, IssuedAt: now.Unix(),
		Expires: now.Add(5 * time.Minute).Unix(), TokenID: "token-1",
	}
}

func TestManagedKeyringIssuesAndSelectsExactKeyID(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	keyring := loadManagedFixture(t, now)
	issuer, err := NewManagedIssuerForAudience(keyring, 15*time.Minute, VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	issuer.random = strings.NewReader("0123456789abcdef")
	token, issued, err := issuer.IssueOwned("device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 1)
	if err != nil || !strings.HasPrefix(token, "v4.voice-2026-q4.") ||
		issued.SigningKeyID != "voice-2026-q4" {
		t.Fatalf("managed issue failed: token=%q claims=%#v err=%v", token, issued, err)
	}
	verifier, err := NewManagedKeyringVerifierForAudience(
		keyring, 15*time.Minute, VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	verified, err := verifier.Verify(token)
	if err != nil || verified.SigningKeyID != "voice-2026-q4" {
		t.Fatalf("managed verify failed: %#v err=%v", verified, err)
	}
	parts := strings.Split(token, ".")
	parts[1] = "voice-unknown"
	if _, err := verifier.Verify(strings.Join(parts, ".")); !errors.Is(err, ErrSignature) {
		t.Fatalf("unknown key ID did not fail without fallback: %v", err)
	}
}

func TestManagedKeyringCoversVoiceAgentAndOTAAudiences(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	keyring := loadManagedFixture(t, now)
	tests := []struct {
		name       string
		audience   string
		prefix     string
		issueToken func(*Issuer) (string, Claims, error)
	}{
		{
			name: "voice", audience: VoiceAudience,
			prefix: "v4.voice-2026-q4.",
			issueToken: func(issuer *Issuer) (string, Claims, error) {
				return issuer.IssueOwned("device-1", "owner-1", "tenant-1",
					"MDEyMzQ1Njc4OWFiY2RlZg", 1)
			},
		},
		{
			name: "agent", audience: AgentAudience,
			prefix: "v4.voice-2026-q4.",
			issueToken: func(issuer *Issuer) (string, Claims, error) {
				return issuer.IssueOwned("device-1", "owner-1", "tenant-1",
					"MDEyMzQ1Njc4OWFiY2RlZg", 1)
			},
		},
		{
			name: "ota", audience: OTAAudience,
			prefix: "v2.voice-2026-q4.",
			issueToken: func(issuer *Issuer) (string, Claims, error) {
				return issuer.IssueForRelease("device-1", "release-1",
					strings.Repeat("a", 64))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer, err := NewManagedIssuerForAudience(keyring, 15*time.Minute,
				test.audience)
			if err != nil {
				t.Fatal(err)
			}
			issuer.now = func() time.Time { return now }
			issuer.random = strings.NewReader("0123456789abcdef")
			token, issued, err := test.issueToken(issuer)
			if err != nil || !strings.HasPrefix(token, test.prefix) ||
				issued.SigningKeyID != "voice-2026-q4" {
				t.Fatalf("managed %s issue failed: token=%q claims=%#v err=%v",
					test.name, token, issued, err)
			}
			verifier, err := NewManagedKeyringVerifierForAudience(keyring,
				15*time.Minute, test.audience)
			if err != nil {
				t.Fatal(err)
			}
			verifier.now = func() time.Time { return now }
			verified, err := verifier.Verify(token)
			if err != nil || verified.Audience != test.audience ||
				verified.SigningKeyID != "voice-2026-q4" {
				t.Fatalf("managed %s verify failed: claims=%#v err=%v",
					test.name, verified, err)
			}
			wrongAudience := AgentAudience
			if test.audience == AgentAudience {
				wrongAudience = VoiceAudience
			}
			wrongVerifier, err := NewManagedKeyringVerifierForAudience(keyring,
				15*time.Minute, wrongAudience)
			if err != nil {
				t.Fatal(err)
			}
			wrongVerifier.now = func() time.Time { return now }
			if _, err := wrongVerifier.Verify(token); !errors.Is(err, ErrClaims) {
				t.Fatalf("managed %s token crossed audience boundary: %v",
					test.name, err)
			}
		})
	}
}

func TestManagedKeyringBoundsRetiringAndLegacyTokens(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	keyring := loadManagedFixture(t, now)
	verifier, err := NewManagedKeyringVerifierForAudience(
		keyring, 15*time.Minute, VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	claims := managedVoiceClaims(now)
	keyedOld := signManagedTestToken(t, managedOldKey, "v4", "voice-2026-q3", claims)
	verified, err := verifier.Verify(keyedOld)
	if err != nil || verified.SigningKeyID != "voice-2026-q3" {
		t.Fatalf("pre-cutover keyed token rejected: %#v err=%v", verified, err)
	}
	legacy := signTestTokenVersion(t, managedOldKey, "v3", claims)
	if _, err := verifier.Verify(legacy); err != nil {
		t.Fatalf("bounded legacy token rejected: %v", err)
	}

	afterCutover := claims
	afterCutover.IssuedAt = now.Add(70 * time.Minute).Unix()
	afterCutover.Expires = now.Add(75 * time.Minute).Unix()
	verifier.now = func() time.Time { return now.Add(70 * time.Minute) }
	if _, err := verifier.Verify(signManagedTestToken(t, managedOldKey, "v4",
		"voice-2026-q3", afterCutover)); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("post-cutover retiring key token accepted: %v", err)
	}
	verifier.now = func() time.Time { return now.Add(2*time.Hour + time.Second) }
	if _, err := verifier.Verify(legacy); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("legacy token accepted after transition deadline: %v", err)
	}
}

func TestManagedKeyringRejectsRollbackWeakFilesAndInvalidDocuments(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	document := managedDocument(now)
	path := writeManagedDocument(t, document)
	if _, err := LoadManagedTokenKeyring(path, 8, now); err == nil {
		t.Fatal("keyring below the approved revision floor was accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManagedTokenKeyring(path, 7, now); err == nil {
		t.Fatal("world-readable keyring was accepted")
	}

	mutations := []func(*managedKeyringDocument){
		func(value *managedKeyringDocument) { value.Keys[0].HMACKeyB64URL = value.Keys[1].HMACKeyB64URL },
		func(value *managedKeyringDocument) { value.Keys[0], value.Keys[1] = value.Keys[1], value.Keys[0] },
		func(value *managedKeyringDocument) { value.Keys[0].State = "active" },
		func(value *managedKeyringDocument) { value.LegacyUnkeyedKeyID = "voice-unknown" },
		func(value *managedKeyringDocument) { value.Keys[0].VerifyUntilUnix = value.Keys[0].IssueBeforeUnix },
	}
	for index, mutate := range mutations {
		candidate := managedDocument(now)
		mutate(&candidate)
		if _, err := LoadManagedTokenKeyring(writeManagedDocument(t, candidate), 7, now); err == nil {
			t.Fatalf("invalid keyring mutation %d was accepted", index)
		}
	}
}

func TestManagedKeyringRequiresDisjointDomains(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	voice := loadManagedFixture(t, now)
	agentDocument := managedDocument(now)
	agentDocument.ActiveKeyID = "agent-2026-q4"
	agentDocument.LegacyUnkeyedKeyID = "agent-2026-q3"
	agentDocument.Keys[0].KeyID = "agent-2026-q3"
	agentDocument.Keys[0].HMACKeyB64URL = base64.RawURLEncoding.EncodeToString(
		[]byte("agent-old-key-0123456789abcdef01234"))
	agentDocument.Keys[1].KeyID = "agent-2026-q4"
	agentDocument.Keys[1].HMACKeyB64URL = base64.RawURLEncoding.EncodeToString(
		[]byte("agent-new-key-0123456789abcdef01234"))
	agent, err := LoadManagedTokenKeyring(writeManagedDocument(t, agentDocument), 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ManagedTokenKeyringsDisjoint(voice, agent) {
		t.Fatal("distinct keyring domains were rejected")
	}
	agent.keys["agent-2026-q3"] = managedTokenKey{
		id: "agent-2026-q3", secret: append([]byte(nil), managedOldKey...),
		state: "retiring", issueBefore: now.Add(time.Hour),
		verifyUntil: now.Add(3 * time.Hour),
	}
	if ManagedTokenKeyringsDisjoint(voice, agent) {
		t.Fatal("cross-domain reused key material was accepted")
	}
}

func TestManagedTokenTransitionValidatesVerifierFirstRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	current := loadManagedDocument(t, managedDocument(now), 7, now)
	target := loadManagedDocument(t, managedRotationTarget(now), 8, now)
	summary, err := ValidateManagedTokenTransition(current, target,
		ManagedTokenTransitionRotate, 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transition != ManagedTokenTransitionRotate ||
		summary.CurrentRevision != 7 || summary.TargetRevision != 8 ||
		summary.CurrentActiveKeyID != "voice-2026-q4" ||
		summary.TargetActiveKeyID != "voice-2027-q1" ||
		summary.CutoverUnix != now.Add(2*time.Hour).Unix() ||
		summary.MinimumDrainUntilUnix != now.Add(2*time.Hour+15*time.Minute+
			managedTokenTransitionSkew).Unix() ||
		summary.OldKeyVerifyUntilUnix != now.Add(24*time.Hour).Unix() {
		t.Fatalf("unexpected transition summary: %#v", summary)
	}
}

func TestManagedTokenTransitionRejectsUnsafeRotationMutations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	current := loadManagedDocument(t, managedDocument(now), 7, now)
	mutations := []func(*managedKeyringDocument){
		func(value *managedKeyringDocument) { value.Revision = 7 },
		func(value *managedKeyringDocument) {
			value.Keys[1].IssueBeforeUnix = now.Add(10 * time.Second).Unix()
		},
		func(value *managedKeyringDocument) {
			value.Keys[1].VerifyUntilUnix = now.Add(3 * time.Hour).Unix()
		},
		func(value *managedKeyringDocument) {
			value.Keys[1].VerifyUntilUnix = now.Add(25 * time.Hour).Unix()
		},
		func(value *managedKeyringDocument) {
			value.Keys[0].VerifyUntilUnix++
		},
		func(value *managedKeyringDocument) {
			value.LegacyUnkeyedKeyID = ""
			value.LegacyUnkeyedVerifyUntilUnix = 0
		},
		func(value *managedKeyringDocument) {
			value.Keys[1].HMACKeyB64URL = base64.RawURLEncoding.EncodeToString(
				[]byte("managed-replaced-key-0123456789abcdef"))
		},
	}
	for index, mutate := range mutations {
		document := managedRotationTarget(now)
		mutate(&document)
		target := loadManagedDocument(t, document, 7, now)
		if _, err := ValidateManagedTokenTransition(current, target,
			ManagedTokenTransitionRotate, 15*time.Minute, now); err == nil {
			t.Fatalf("unsafe rotation mutation %d was accepted", index)
		}
	}
	if _, err := ValidateManagedTokenTransition(current,
		loadManagedDocument(t, managedRotationTarget(now), 8, now),
		ManagedTokenTransitionRotate, 15*time.Minute,
		now.Add(2*time.Hour)); err == nil {
		t.Fatal("rotation preflight accepted a cutover that was no longer future")
	}
}

func TestManagedTokenTransitionValidatesForwardRecovery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	current := loadManagedDocument(t, managedRotationTarget(now), 8, now)
	target := loadManagedDocument(t, managedRecoveryTarget(now), 9, now)
	summary, err := ValidateManagedTokenTransition(current, target,
		ManagedTokenTransitionForwardRecover, 15*time.Minute, now)
	if err != nil || summary.CurrentActiveKeyID != "voice-2027-q1" ||
		summary.TargetActiveKeyID != "voice-2026-q4" ||
		summary.CutoverUnix != now.Add(3*time.Hour).Unix() {
		t.Fatalf("forward recovery rejected: summary=%#v err=%v", summary, err)
	}
	if _, err := ValidateManagedTokenTransition(current, target,
		ManagedTokenTransitionRotate, 15*time.Minute, now); err == nil {
		t.Fatal("forward recovery was accepted as a new-key rotation")
	}

	legacyRecovery := managedRecoveryTarget(now)
	legacyRecovery.ActiveKeyID = "voice-2026-q3"
	legacyRecovery.LegacyUnkeyedKeyID = ""
	legacyRecovery.LegacyUnkeyedVerifyUntilUnix = 0
	legacyRecovery.Keys[0].State = "active"
	legacyRecovery.Keys[0].IssueBeforeUnix = 0
	legacyRecovery.Keys[0].VerifyUntilUnix = now.Add(48 * time.Hour).Unix()
	legacyRecovery.Keys[1].State = "retiring"
	legacyRecovery.Keys[1].IssueBeforeUnix = now.Add(4 * time.Hour).Unix()
	legacyRecovery.Keys[2].State = "retiring"
	legacyRecovery.Keys[2].IssueBeforeUnix = now.Add(3 * time.Hour).Unix()
	if _, err := ValidateManagedTokenTransition(current,
		loadManagedDocument(t, legacyRecovery, 9, now),
		ManagedTokenTransitionForwardRecover, 15*time.Minute, now); err == nil {
		t.Fatal("legacy unkeyed transition key was reactivated")
	}
}
