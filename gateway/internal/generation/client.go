package generation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type Client struct {
	baseURL   string
	principal Principal
	http      *http.Client
	now       func() time.Time
}

func NewClient(baseURL string, principal Principal, transport http.RoundTripper,
	allowInsecure bool) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.User != nil ||
		(parsed.Scheme != "https" && !(allowInsecure && parsed.Scheme == "http")) ||
		!auth.ValidIdentifier(principal.ID, 64) || len(principal.Key) < 32 ||
		(principal.Role != "publisher" && principal.Role != "controlplane" &&
			principal.Role != "firmwareorigin") {
		return nil, fmt.Errorf("generation coordinator client inputs are invalid")
	}
	if strings.HasSuffix(baseURL, "/") {
		return nil, fmt.Errorf("generation coordinator URL must not end in slash")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Client{
		baseURL: baseURL, principal: Principal{ID: principal.ID,
			Role: principal.Role, Key: append([]byte(nil), principal.Key...)},
		http: &http.Client{Transport: transport, Timeout: 4 * time.Second},
		now:  time.Now,
	}, nil
}

func (client *Client) GetState(ctx context.Context) (StateView, error) {
	return client.call(ctx, http.MethodGet, pathState, nil)
}

func (client *Client) Publish(ctx context.Context, request PublishRequest) (StateView, error) {
	if client.principal.Role != "publisher" {
		return StateView{}, fmt.Errorf("only publisher may publish a generation")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return StateView{}, err
	}
	return client.call(ctx, http.MethodPost, pathPublish, payload)
}

func (client *Client) Abort(ctx context.Context, request AbortRequest) (StateView, error) {
	if client.principal.Role != "publisher" {
		return StateView{}, fmt.Errorf("only publisher may abort a generation")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return StateView{}, err
	}
	return client.call(ctx, http.MethodPost, pathAbort, payload)
}

func (client *Client) Acknowledge(ctx context.Context,
	request AckRequest) (StateView, error) {
	if client.principal.Role != "controlplane" && client.principal.Role != "firmwareorigin" {
		return StateView{}, fmt.Errorf("only replica may acknowledge a generation")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return StateView{}, err
	}
	return client.call(ctx, http.MethodPost, pathAck, payload)
}

func (client *Client) call(ctx context.Context, method, path string,
	payload []byte) (StateView, error) {
	nonce, err := randomNonce()
	if err != nil {
		return StateView{}, err
	}
	timestamp := strconv.FormatInt(client.now().UTC().Unix(), 10)
	bodyDigest := sha256.Sum256(payload)
	canonical := canonicalAPIRequest(client.principal.ID, method, path,
		timestamp, nonce, hex.EncodeToString(bodyDigest[:]))
	mac := hmac.New(sha256.New, client.principal.Key)
	_, _ = mac.Write([]byte(canonical))
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path,
		bytes.NewReader(payload))
	if err != nil {
		return StateView{}, err
	}
	request.Header.Set(HeaderPrincipal, client.principal.ID)
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return StateView{}, fmt.Errorf("generation coordinator request failed: %w", err)
	}
	defer response.Body.Close()
	responsePayload, readErr := io.ReadAll(io.LimitReader(response.Body, maximumAPIBytes+1))
	if readErr != nil || len(responsePayload) > maximumAPIBytes {
		return StateView{}, fmt.Errorf("generation coordinator response is invalid")
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusConflict {
			return StateView{}, ErrConflict
		}
		return StateView{}, fmt.Errorf("generation coordinator rejected request: status %d",
			response.StatusCode)
	}
	signatureText := response.Header.Get(HeaderResponseSignature)
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return StateView{}, fmt.Errorf("generation coordinator response signature is invalid")
	}
	responseDigest := sha256.Sum256(responsePayload)
	canonical = canonicalAPIResponse(client.principal.ID, nonce,
		response.StatusCode, hex.EncodeToString(responseDigest[:]))
	mac = hmac.New(sha256.New, client.principal.Key)
	_, _ = mac.Write([]byte(canonical))
	if subtle.ConstantTimeCompare(signature, mac.Sum(nil)) != 1 {
		return StateView{}, fmt.Errorf("generation coordinator response signature is invalid")
	}
	var view StateView
	decoder := json.NewDecoder(bytes.NewReader(responsePayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil || ensureJSONEOF(decoder) != nil {
		return StateView{}, fmt.Errorf("generation coordinator state is invalid")
	}
	canonicalPayload, _ := json.Marshal(view)
	canonicalPayload = append(canonicalPayload, '\n')
	if !bytes.Equal(canonicalPayload, responsePayload) || validateStateView(view) != nil {
		return StateView{}, fmt.Errorf("generation coordinator state is invalid")
	}
	return view, nil
}

func validateStateView(view StateView) error {
	if view.Schema != 1 || view.Revision == 0 || !validSHA256(view.RecordSHA256) ||
		!validGeneration(view.Active) || !validReplicas(view.RequiredReplicas) ||
		view.UpdatedAt < 1609459200 || view.UpdatedAt > 4102444800 {
		return fmt.Errorf("state view fields are invalid")
	}
	state := State{
		Schema: view.Schema, Revision: view.Revision,
		PreviousRecordSHA256: zeroDigest, Phase: view.Phase, Active: view.Active,
		Pending: view.Pending, RequiredReplicas: view.RequiredReplicas,
		Acknowledgements: view.Acknowledgements,
		PrepareDeadline:  view.PrepareDeadline, DrainUntil: view.DrainUntil,
		CommitDeadline: view.CommitDeadline, UpdatedAt: view.UpdatedAt,
	}
	return validateState(state)
}
