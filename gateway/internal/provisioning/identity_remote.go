package provisioning

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	IdentitySnapshotMediaType = "application/vnd.xiaozhi.device-identity.v2+json"
	identityRevisionHeader    = "X-Xiaozhi-Identity-Revision"
	identityMinimumHeader     = "X-Xiaozhi-Identity-Min-Revision"
)

// RegistryUpdater is implemented by local-file and remote identity sources.
type RegistryUpdater interface {
	Reload() (bool, SnapshotStatus, error)
	Run(context.Context, time.Duration, func(ReloadEvent))
}

// RemoteRegistryReloader obtains signed snapshots through a mutually
// authenticated HTTPS channel. The Ed25519 signature remains the content trust
// boundary; transport identity alone never activates a snapshot.
type RemoteRegistryReloader struct {
	endpoint     *url.URL
	publicKey    ed25519.PublicKey
	signingKeyID string
	purpose      string
	registry     *Registry
	client       *http.Client
	now          func() time.Time
	minimum      uint64

	mu   sync.Mutex
	etag string
}

// NewIdentityMTLSClient creates a private, non-proxying HTTP client with a
// dedicated CA and one client identity. The key file must be mode 0600 or
// stricter. The returned client refuses redirects.
func NewIdentityMTLSClient(caPath, certificatePath, keyPath string,
	timeout time.Duration) (*http.Client, error) {
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, fmt.Errorf("device identity request timeout must be 1 through 30 seconds")
	}
	caPEM, err := readBoundedRegularFile(caPath, 1024*1024, false)
	if err != nil {
		return nil, fmt.Errorf("load device identity CA: %w", err)
	}
	certificatePEM, err := readBoundedRegularFile(certificatePath, 1024*1024, false)
	if err != nil {
		return nil, fmt.Errorf("load device identity client certificate: %w", err)
	}
	keyFile, err := openConfidentialRegularFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load device identity client key: %w", err)
	}
	keyPEM, err := io.ReadAll(io.LimitReader(keyFile, 1024*1024+1))
	_ = keyFile.Close()
	if err != nil || len(keyPEM) == 0 || len(keyPEM) > 1024*1024 {
		return nil, fmt.Errorf("load device identity client key: invalid key file")
	}
	clientCertificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load device identity client keypair: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("device identity CA bundle contains no certificate")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      roots,
			Certificates: []tls.Certificate{clientCertificate},
		},
		TLSHandshakeTimeout: timeout,
		DisableCompression:  true,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("device identity redirects are forbidden")
		},
	}, nil
}

// LoadRemoteReloadableRegistry performs a synchronous, fail-closed initial
// fetch before returning the registry used by the service.
func LoadRemoteReloadableRegistry(ctx context.Context, endpoint,
	publicKeyPath, signingKeyID, expectedPurpose string,
	minimumRevision uint64, client *http.Client,
	now func() time.Time) (*Registry, *RemoteRegistryReloader, error) {
	if ctx == nil || minimumRevision == 0 {
		return nil, nil, fmt.Errorf("remote device identity context and revision floor are required")
	}
	if now == nil {
		now = time.Now
	}
	publicKey, err := LoadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	reloader, err := newRemoteRegistryReloader(endpoint, publicKey,
		signingKeyID, expectedPurpose, minimumRevision, client, now)
	if err != nil {
		return nil, nil, err
	}
	snapshot, etag, notModified, err := reloader.fetch(ctx, SnapshotStatus{}, "")
	if err != nil {
		return nil, nil, err
	}
	if notModified || snapshot == nil || snapshot.revision < minimumRevision {
		return nil, nil, fmt.Errorf("remote device identity initial snapshot is below the configured revision floor")
	}
	registry, err := NewRegistryFromSnapshot(snapshot, now)
	if err != nil {
		return nil, nil, err
	}
	reloader.registry = registry
	reloader.etag = etag
	return registry, reloader, nil
}

func newRemoteRegistryReloader(endpoint string, publicKey ed25519.PublicKey,
	signingKeyID, expectedPurpose string, minimumRevision uint64,
	client *http.Client, now func() time.Time) (*RemoteRegistryReloader, error) {
	parsed, err := url.Parse(endpoint)
	expectedPath := "/v1/device-identity/" + expectedPurpose
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.Path != expectedPath || parsed.RawPath != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" ||
		len(publicKey) != ed25519.PublicKeySize ||
		!auth.ValidIdentifier(signingKeyID, 64) || minimumRevision == 0 ||
		client == nil || client.Transport == nil || client.Timeout < time.Second ||
		client.Timeout > 30*time.Second ||
		(expectedPurpose != AccessSnapshotPurpose &&
			expectedPurpose != ProofSnapshotPurpose) {
		return nil, fmt.Errorf("invalid remote device identity configuration")
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("device identity redirects are forbidden")
	}
	if now == nil {
		now = time.Now
	}
	return &RemoteRegistryReloader{
		endpoint: parsed, publicKey: append(ed25519.PublicKey(nil), publicKey...),
		signingKeyID: signingKeyID, purpose: expectedPurpose,
		minimum: minimumRevision, client: &clientCopy, now: now,
	}, nil
}

func (reloader *RemoteRegistryReloader) Reload() (bool, SnapshotStatus, error) {
	return reloader.reload(context.Background())
}

func (reloader *RemoteRegistryReloader) reload(ctx context.Context) (bool,
	SnapshotStatus, error) {
	if reloader == nil || reloader.registry == nil || ctx == nil {
		return false, SnapshotStatus{}, fmt.Errorf("remote device identity reloader is required")
	}
	reloader.mu.Lock()
	defer reloader.mu.Unlock()
	status := reloader.registry.Status()
	snapshot, etag, notModified, err := reloader.fetch(ctx, status, reloader.etag)
	if err != nil {
		return false, reloader.registry.Status(), err
	}
	if notModified {
		return false, reloader.registry.Status(), nil
	}
	if snapshot.revision < reloader.minimum {
		return false, reloader.registry.Status(),
			fmt.Errorf("remote device identity snapshot is below the configured revision floor")
	}
	changed, err := reloader.registry.ApplySnapshot(snapshot)
	if err != nil {
		return false, reloader.registry.Status(), err
	}
	if changed || snapshot.revision == reloader.registry.Status().Revision {
		reloader.etag = etag
	}
	return changed, reloader.registry.Status(), nil
}

func (reloader *RemoteRegistryReloader) Run(ctx context.Context,
	interval time.Duration, notify func(ReloadEvent)) {
	if reloader == nil || ctx == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, status, err := reloader.reload(ctx)
			if notify != nil {
				notify(ReloadEvent{Changed: changed, Status: status, Err: err})
			}
		}
	}
}

func (reloader *RemoteRegistryReloader) fetch(ctx context.Context,
	current SnapshotStatus, etag string) (*Snapshot, string, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		reloader.endpoint.String(), nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("create remote device identity request: %w", err)
	}
	request.Header.Set("Accept", IdentitySnapshotMediaType)
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("User-Agent", "xiaozhi-identity-client/1")
	request.Header.Set(identityMinimumHeader,
		strconv.FormatUint(maxUint64(reloader.minimum, current.Revision), 10))
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := reloader.client.Do(request)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch remote device identity snapshot: %w", err)
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		return nil, "", false, fmt.Errorf("remote device identity response is not protected by TLS 1.2 or newer")
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) ||
		response.Header.Get("Content-Encoding") != "" {
		return nil, "", false, fmt.Errorf("remote device identity cache/encoding policy is invalid")
	}
	revision, err := canonicalRevision(response.Header.Get(identityRevisionHeader))
	if err != nil {
		return nil, "", false, err
	}
	responseETag := response.Header.Get("ETag")
	if response.StatusCode == http.StatusNotModified {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
		if readErr != nil || len(body) != 0 || etag == "" ||
			responseETag != etag || revision != current.Revision {
			return nil, "", false, fmt.Errorf("remote device identity not-modified response is inconsistent")
		}
		return nil, etag, true, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("remote device identity returned status %d", response.StatusCode)
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != IdentitySnapshotMediaType || len(parameters) != 0 ||
		response.ContentLength <= 0 || response.ContentLength > maximumRegistryBytes {
		return nil, "", false, fmt.Errorf("remote device identity response metadata is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumRegistryBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumRegistryBytes ||
		int64(len(payload)) != response.ContentLength {
		return nil, "", false, fmt.Errorf("remote device identity response size is invalid")
	}
	snapshot, err := ParseSignedRegistrySnapshot(strings.NewReader(string(payload)),
		reloader.publicKey, reloader.signingKeyID, reloader.now().UTC())
	if err != nil {
		return nil, "", false, err
	}
	if snapshot.state.purpose != reloader.purpose || snapshot.revision != revision {
		return nil, "", false, fmt.Errorf("remote device identity purpose/revision is inconsistent")
	}
	expectedETag := fmt.Sprintf("\"sha256:%x\"", snapshot.digest)
	if responseETag != expectedETag {
		return nil, "", false, fmt.Errorf("remote device identity ETag is inconsistent")
	}
	return snapshot, responseETag, false, nil
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

func canonicalRevision(value string) (uint64, error) {
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != value {
		return 0, fmt.Errorf("remote device identity revision header is invalid")
	}
	return revision, nil
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func readBoundedRegularFile(path string, maximum int64,
	confidential bool) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, fmt.Errorf("file path and size bound are required")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maximum || (confidential && info.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("file is invalid")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if int64(len(payload)) != info.Size() {
		return nil, fmt.Errorf("file size changed while reading")
	}
	return payload, nil
}
