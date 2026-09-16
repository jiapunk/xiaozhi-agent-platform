// Package factorytime implements the server side of the M60 sacrificial
// trusted-time protocol. It deliberately contains no signing-key
// implementation: production signing is supplied by an external HSM/KMS
// adapter through the Signer interface.
package factorytime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	EndpointPath          = "/v1/factory/trusted-time"
	RequestSchema         = "xz-sacrificial-trusted-time-request-v1"
	ReceiptSchema         = "xz-sacrificial-trusted-time-receipt-v1"
	Environment           = "SACRIFICIAL_HARDWARE_AUTHORIZATION"
	Scope                 = "SACRIFICIAL_ATTEMPT_CONSUMPTION_TIME"
	RequestResult         = "TRUSTED_TIME_REQUESTED"
	ReceiptResult         = "TRUSTED_TIME_ATTESTED"
	SignatureAlgorithm    = "Ed25519"
	MaximumRequestBytes   = 64 * 1024
	MaximumResponseBytes  = 16 * 1024
	MaximumReceiptSeconds = 10
	SignatureDomain       = "xz-sacrificial-trusted-time-receipt-v1\x00"
)

var (
	ErrInvalid       = errors.New("invalid trusted-time request")
	ErrUnauthorized  = errors.New("unauthorized factory station")
	ErrReplay        = errors.New("trusted-time request replay")
	ErrOutsideWindow = errors.New("authorization is outside its time window")
	ErrUnavailable   = errors.New("trusted-time authority unavailable")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,128}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	devicePattern     = regexp.MustCompile(`^xz-[0-9a-f]{12}$`)
	macPattern        = regexp.MustCompile(`^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$`)
)

type Ledger struct {
	PolicySHA256 string `json:"policy_sha256"`
	PolicyID     string `json:"policy_id"`
	LedgerID     string `json:"ledger_id"`
}

type Authorization struct {
	PlanSHA256 string `json:"plan_sha256"`
	PlanID     string `json:"plan_id"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
}

type Transaction struct {
	AttemptID string `json:"attempt_id"`
	DeviceID  string `json:"device_id"`
	BaseMAC   string `json:"base_mac"`
}

type Station struct {
	ID             string `json:"id"`
	FixtureID      string `json:"fixture_id"`
	FixtureVersion string `json:"fixture_version"`
}

type Request struct {
	Schema        string        `json:"schema"`
	Environment   string        `json:"environment"`
	Scope         string        `json:"scope"`
	RequestID     string        `json:"request_id"`
	NonceB64URL   string        `json:"nonce_b64url"`
	Ledger        Ledger        `json:"ledger"`
	Authorization Authorization `json:"authorization"`
	Transaction   Transaction   `json:"transaction"`
	Station       Station       `json:"station"`
	Result        string        `json:"result"`
}

type Receipt struct {
	Schema             string        `json:"schema"`
	Environment        string        `json:"environment"`
	Scope              string        `json:"scope"`
	RequestSHA256      string        `json:"request_sha256"`
	RequestID          string        `json:"request_id"`
	NonceB64URL        string        `json:"nonce_b64url"`
	Ledger             Ledger        `json:"ledger"`
	Authorization      Authorization `json:"authorization"`
	Transaction        Transaction   `json:"transaction"`
	Station            Station       `json:"station"`
	AuthorityKeyID     string        `json:"authority_key_id"`
	ObservedAt         string        `json:"observed_at"`
	ExpiresAt          string        `json:"expires_at"`
	Result             string        `json:"result"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
	SignatureB64URL    string        `json:"signature_b64url,omitempty"`
}

func ParseRequest(data []byte) (Request, [32]byte, error) {
	var zero [32]byte
	if len(data) == 0 || len(data) > MaximumRequestBytes ||
		rejectDuplicateMembers(data) != nil {
		return Request{}, zero, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, zero, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Request{}, zero, ErrInvalid
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, zero, err
	}
	canonical, err := CanonicalJSON(request)
	if err != nil || !bytes.Equal(canonical, data) {
		return Request{}, zero, ErrInvalid
	}
	return request, sha256.Sum256(data), nil
}

func ValidateRequest(request Request) error {
	if request.Schema != RequestSchema || request.Environment != Environment ||
		request.Scope != Scope || request.Result != RequestResult ||
		!validIdentifier(request.RequestID) || !validNonce(request.NonceB64URL) {
		return ErrInvalid
	}
	issued, expires, err := validateSubject(request.Ledger,
		request.Authorization, request.Transaction, request.Station)
	if err != nil {
		return ErrInvalid
	}
	if !issued.Before(expires) {
		return ErrInvalid
	}
	return nil
}

func ParseUnsignedReceipt(data []byte) (Receipt, error) {
	if len(data) == 0 || len(data) > MaximumResponseBytes ||
		rejectDuplicateMembers(data) != nil {
		return Receipt{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Receipt{}, ErrInvalid
	}
	if err := ValidateUnsignedReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := CanonicalJSON(receipt)
	if err != nil || !bytes.Equal(canonical, data) {
		return Receipt{}, ErrInvalid
	}
	return receipt, nil
}

func ValidateUnsignedReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema || receipt.Environment != Environment ||
		receipt.Scope != Scope || receipt.Result != ReceiptResult ||
		receipt.SignatureAlgorithm != SignatureAlgorithm ||
		receipt.SignatureB64URL != "" || !validDigest(receipt.RequestSHA256) ||
		!validIdentifier(receipt.RequestID) || !validNonce(receipt.NonceB64URL) ||
		!validIdentifier(receipt.AuthorityKeyID) {
		return ErrInvalid
	}
	planIssued, planExpires, err := validateSubject(receipt.Ledger,
		receipt.Authorization, receipt.Transaction, receipt.Station)
	if err != nil {
		return ErrInvalid
	}
	observed, err := parseTimestamp(receipt.ObservedAt)
	if err != nil {
		return ErrInvalid
	}
	expires, err := parseTimestamp(receipt.ExpiresAt)
	if err != nil || !observed.Before(expires) ||
		expires.After(observed.Add(MaximumReceiptSeconds*time.Second)) ||
		observed.Before(planIssued) || observed.After(planExpires) {
		return ErrInvalid
	}
	return nil
}

func validateSubject(ledger Ledger, authorization Authorization,
	transaction Transaction, station Station) (time.Time, time.Time, error) {
	if !validDigest(ledger.PolicySHA256) ||
		!validIdentifier(ledger.PolicyID) || !validIdentifier(ledger.LedgerID) ||
		!validDigest(authorization.PlanSHA256) ||
		!validIdentifier(authorization.PlanID) ||
		!validIdentifier(transaction.AttemptID) ||
		!devicePattern.MatchString(transaction.DeviceID) ||
		!macPattern.MatchString(transaction.BaseMAC) ||
		transaction.DeviceID != "xz-"+
			strings.ToLower(strings.ReplaceAll(transaction.BaseMAC, ":", "")) ||
		!validIdentifier(station.ID) || !validIdentifier(station.FixtureID) ||
		!validIdentifier(station.FixtureVersion) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	issued, err := parseTimestamp(authorization.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	expires, err := parseTimestamp(authorization.ExpiresAt)
	if err != nil || !issued.Before(expires) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	return issued, expires, nil
}

// CanonicalJSON matches Python json.dumps(sort_keys=True, separators=(",",":"),
// ensure_ascii=True) for this ASCII-only protocol.
func CanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.Year() < 1 ||
		parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, ErrInvalid
	}
	return parsed.UTC(), nil
}

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }
func validDigest(value string) bool     { return digestPattern.MatchString(value) }

func validNonce(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func rejectDuplicateMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return ErrInvalid
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("%w: duplicate member", ErrInvalid)
			}
			seen[name] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
