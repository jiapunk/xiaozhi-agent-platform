package pushdelivery

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	googleOAuthTokenEndpoint    = "https://oauth2.googleapis.com/token"
	googleFCMScope              = "https://www.googleapis.com/auth/firebase.messaging"
	googleJWTGrantType          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	googleMetadataTokenEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?enforce_scopes=true&scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Ffirebase.messaging"
	maximumGoogleTokenResponse  = 8 * 1024
)

type GoogleServiceAccountTokenSource struct {
	client   *http.Client
	signer   crypto.Signer
	email    string
	keyID    string
	endpoint string
	now      func() time.Time
}

var _ OAuthAccessTokenSource = (*GoogleServiceAccountTokenSource)(nil)

func NewGoogleServiceAccountTokenSource(client *http.Client,
	signer crypto.Signer, email, keyID string) (*GoogleServiceAccountTokenSource, error) {
	if signer == nil || !validServiceAccountEmail(email) ||
		!validGoogleKeyID(keyID) || client == nil ||
		client.Timeout < 100*time.Millisecond || client.Timeout > 10*time.Second {
		return nil, ErrInvalid
	}
	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok || publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() < 2048 ||
		publicKey.E < 3 {
		return nil, ErrInvalid
	}
	hardened, err := hardenedHTTPClient(client, false, tls.VersionTLS12)
	if err != nil {
		return nil, err
	}
	return &GoogleServiceAccountTokenSource{client: hardened, signer: signer,
		email: email, keyID: keyID, endpoint: googleOAuthTokenEndpoint,
		now: time.Now}, nil
}

func (source *GoogleServiceAccountTokenSource) AccessToken(ctx context.Context) (
	OAuthAccessToken, error) {
	if source == nil || ctx == nil || source.client == nil || source.signer == nil {
		return OAuthAccessToken{}, ErrInvalid
	}
	now := source.now().UTC()
	assertion, err := source.assertion(now)
	if err != nil {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google assertion", ErrUnavailable)
	}
	form := url.Values{"grant_type": {googleJWTGrantType},
		"assertion": {assertion}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		source.endpoint, strings.NewReader(form))
	if err != nil {
		return OAuthAccessToken{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := source.client.Do(request)
	if err != nil {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google OAuth transport", ErrUnavailable)
	}
	defer response.Body.Close()
	return decodeGoogleAccessToken(response, now)
}

func (source *GoogleServiceAccountTokenSource) assertion(now time.Time) (string, error) {
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}{Algorithm: "RS256", Type: "JWT", KeyID: source.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Issuer   string `json:"iss"`
		Scope    string `json:"scope"`
		Audience string `json:"aud"`
		Expires  int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
	}{Issuer: source.email, Scope: googleFCMScope,
		Audience: googleOAuthTokenEndpoint, Expires: now.Add(time.Hour).Unix(),
		IssuedAt: now.Unix()})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := source.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	publicKey, ok := source.signer.Public().(*rsa.PublicKey)
	if !ok || len(signature) != publicKey.Size() ||
		rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature) != nil {
		return "", ErrInvalid
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type GoogleMetadataTokenSource struct {
	client   *http.Client
	endpoint string
	now      func() time.Time
}

var _ OAuthAccessTokenSource = (*GoogleMetadataTokenSource)(nil)

func NewGoogleMetadataTokenSource(client *http.Client) (
	*GoogleMetadataTokenSource, error) {
	if client == nil || client.Timeout < 100*time.Millisecond ||
		client.Timeout > 3*time.Second {
		return nil, ErrInvalid
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil || transport.Proxy != nil {
		return nil, ErrInvalid
	}
	copyClient := *client
	copyTransport := transport.Clone()
	copyTransport.Proxy = nil
	copyClient.Transport = copyTransport
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &GoogleMetadataTokenSource{client: &copyClient,
		endpoint: googleMetadataTokenEndpoint, now: time.Now}, nil
}

func (source *GoogleMetadataTokenSource) AccessToken(ctx context.Context) (
	OAuthAccessToken, error) {
	if source == nil || ctx == nil || source.client == nil {
		return OAuthAccessToken{}, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		source.endpoint, nil)
	if err != nil {
		return OAuthAccessToken{}, ErrUnavailable
	}
	request.Header.Set("Metadata-Flavor", "Google")
	request.Header.Set("Accept", "application/json")
	response, err := source.client.Do(request)
	if err != nil {
		return OAuthAccessToken{}, fmt.Errorf("%w: metadata transport", ErrUnavailable)
	}
	defer response.Body.Close()
	if response.Header.Get("Metadata-Flavor") != "Google" {
		return OAuthAccessToken{}, fmt.Errorf("%w: metadata response", ErrUnavailable)
	}
	return decodeGoogleAccessToken(response, source.now().UTC())
}

func decodeGoogleAccessToken(response *http.Response,
	now time.Time) (OAuthAccessToken, error) {
	if response == nil {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google token rejected", ErrUnavailable)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google token content type", ErrUnavailable)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body,
		maximumGoogleTokenResponse+1))
	if err != nil || len(body) == 0 || len(body) > maximumGoogleTokenResponse {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google token response", ErrUnavailable)
	}
	if response.StatusCode != http.StatusOK {
		if (response.StatusCode == http.StatusBadRequest ||
			response.StatusCode == http.StatusUnauthorized) &&
			googleCredentialRejected(body) {
			return OAuthAccessToken{}, fmt.Errorf("%w: %w: Google token grant",
				ErrUnavailable, ErrCredentialRejected)
		}
		return OAuthAccessToken{}, fmt.Errorf("%w: Google token rejected", ErrUnavailable)
	}
	var output struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&output); err != nil || output.TokenType != "Bearer" ||
		!validBearer(output.AccessToken) || output.ExpiresIn < 60 ||
		output.ExpiresIn > 7200 {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google token fields", ErrUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return OAuthAccessToken{}, fmt.Errorf("%w: Google token trailing data", ErrUnavailable)
	}
	return OAuthAccessToken{Value: output.AccessToken,
		ExpiresAt: now.Add(time.Duration(output.ExpiresIn) * time.Second)}, nil
}

func googleCredentialRejected(body []byte) bool {
	if strictjson.RejectDuplicateFields(body) != nil {
		return false
	}
	var output struct {
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&output); err != nil ||
		(output.Error != "invalid_grant" && output.Error != "invalid_client") {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func validServiceAccountEmail(value string) bool {
	if len(value) < 6 || len(value) > 254 || strings.Count(value, "@") != 1 ||
		!strings.HasSuffix(value, ".gserviceaccount.com") {
		return false
	}
	for _, character := range []byte(value) {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

func validGoogleKeyID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '-' &&
			character != '_' {
			return false
		}
	}
	return true
}
