package s3camdev

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	speakerIdentityFileHeader        = "XZSPK1"
	maximumSpeakerProfiles           = 6
	maximumSpeakerEnrollmentSamples  = 3
	maximumSpeakerEmbeddingDimension = 1024
	minimumSpeakerAudioPackets       = 30
	maximumSpeakerAudioPackets       = 750
	speakerAmbiguityMargin           = 0.05
	maximumSpeakerResponseBytes      = 32 * 1024
)

type SpeakerIdentityConfig struct {
	EmbeddingURL string
	StorePath    string
	EncodedKey   string
	Threshold    float64
	HTTPClient   *http.Client
}

type SpeakerMatch struct {
	ID          string
	DisplayName string
	Similarity  float64
	Known       bool
}

type SpeakerProfileSummary struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Samples     int    `json:"samples"`
}

type speakerProfile struct {
	ID          string      `json:"id"`
	DisplayName string      `json:"display_name"`
	Embeddings  [][]float32 `json:"embeddings"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type speakerEmbedder interface {
	Embed(context.Context, [][]byte) ([]float32, error)
}

type SpeakerIdentityService struct {
	mu        sync.RWMutex
	path      string
	aead      cipher.AEAD
	threshold float64
	embedder  speakerEmbedder
	profiles  map[string]speakerProfile
}

type httpSpeakerEmbedder struct {
	endpoint *url.URL
	client   *http.Client
}

func NewSpeakerIdentityService(config SpeakerIdentityConfig) (*SpeakerIdentityService, error) {
	if strings.TrimSpace(config.StorePath) == "" {
		return nil, fmt.Errorf("speaker identity store file is required")
	}
	embedder, err := newHTTPSpeakerEmbedder(config.EmbeddingURL, config.HTTPClient)
	if err != nil {
		return nil, err
	}
	return newSpeakerIdentityService(
		config.StorePath, config.EncodedKey, config.Threshold, embedder)
}

func newSpeakerIdentityService(path, encodedKey string, threshold float64,
	embedder speakerEmbedder) (*SpeakerIdentityService, error) {
	if embedder == nil {
		return nil, fmt.Errorf("speaker embedder is required")
	}
	if threshold == 0 {
		threshold = 0.60
	}
	if threshold < 0.30 || threshold > 0.95 {
		return nil, fmt.Errorf("speaker identity threshold is invalid")
	}
	service := &SpeakerIdentityService{
		path: path, threshold: threshold, embedder: embedder,
		profiles: make(map[string]speakerProfile),
	}
	if path != "" {
		key, err := decodeMemoryKey(encodedKey)
		if err != nil {
			return nil, fmt.Errorf("speaker identity key: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("initialize speaker identity encryption: %w", err)
		}
		service.aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("initialize speaker identity authentication: %w", err)
		}
		if err := service.load(); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func newHTTPSpeakerEmbedder(rawURL string, client *http.Client) (*httpSpeakerEmbedder, error) {
	endpoint, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil ||
		endpoint.Path != "/v1/embedding" || endpoint.RawQuery != "" ||
		endpoint.Fragment != "" {
		return nil, fmt.Errorf("speaker embedding URL must be an exact loopback HTTP /v1/embedding URL")
	}
	host := endpoint.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("speaker embedding URL must use loopback")
	}
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	return &httpSpeakerEmbedder{endpoint: endpoint, client: client}, nil
}

func (embedder *httpSpeakerEmbedder) Embed(ctx context.Context,
	packets [][]byte) ([]float32, error) {
	if len(packets) < minimumSpeakerAudioPackets ||
		len(packets) > maximumSpeakerAudioPackets {
		return nil, fmt.Errorf("speaker audio must be between %.1f and %.1f seconds",
			float64(minimumSpeakerAudioPackets*opusFrameDurationMS)/1000,
			float64(maximumSpeakerAudioPackets*opusFrameDurationMS)/1000)
	}
	ogg, err := encodeOggOpus(packets, 16000)
	if err != nil {
		return nil, fmt.Errorf("encode speaker audio: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		embedder.endpoint.String(), bytes.NewReader(ogg))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "audio/ogg")
	response, err := embedder.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call speaker embedding service: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumSpeakerResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read speaker embedding response: %w", err)
	}
	if len(data) > maximumSpeakerResponseBytes || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("speaker embedding service returned status %d", response.StatusCode)
	}
	var result struct {
		Dimension int    `json:"dimension"`
		Embedding string `json:"embedding"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.Dimension <= 0 ||
		result.Dimension > maximumSpeakerEmbeddingDimension {
		return nil, fmt.Errorf("speaker embedding service returned invalid JSON")
	}
	raw, err := base64.StdEncoding.DecodeString(result.Embedding)
	if err != nil || len(raw) != result.Dimension*4 {
		return nil, fmt.Errorf("speaker embedding service returned invalid vector")
	}
	vector := make([]float32, result.Dimension)
	for index := range vector {
		vector[index] = math.Float32frombits(binary.LittleEndian.Uint32(raw[index*4:]))
	}
	return normalizeSpeakerEmbedding(vector)
}

func (service *SpeakerIdentityService) ProfileCount() int {
	if service == nil {
		return 0
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	return len(service.profiles)
}

func (service *SpeakerIdentityService) Profiles() []SpeakerProfileSummary {
	if service == nil {
		return nil
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	profiles := make([]SpeakerProfileSummary, 0, len(service.profiles))
	for _, profile := range service.profiles {
		profiles = append(profiles, SpeakerProfileSummary{
			ID: profile.ID, DisplayName: profile.DisplayName,
			Samples: len(profile.Embeddings),
		})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles
}

func (service *SpeakerIdentityService) Identify(ctx context.Context,
	packets [][]byte) (SpeakerMatch, error) {
	if service == nil || service.ProfileCount() == 0 {
		return SpeakerMatch{}, nil
	}
	embedding, err := service.embedder.Embed(ctx, packets)
	if err != nil {
		return SpeakerMatch{}, err
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	best := SpeakerMatch{Similarity: -1}
	second := -1.0
	for _, profile := range service.profiles {
		centroid, centroidErr := averageSpeakerEmbeddings(profile.Embeddings)
		if centroidErr != nil || len(centroid) != len(embedding) {
			continue
		}
		similarity := speakerCosineSimilarity(embedding, centroid)
		if similarity > best.Similarity {
			second = best.Similarity
			best = SpeakerMatch{
				ID: profile.ID, DisplayName: profile.DisplayName,
				Similarity: similarity,
			}
		} else if similarity > second {
			second = similarity
		}
	}
	best.Known = best.ID != "" && best.Similarity >= service.threshold &&
		(second < 0 || best.Similarity-second >= speakerAmbiguityMargin)
	if !best.Known {
		return SpeakerMatch{Similarity: best.Similarity}, nil
	}
	return best, nil
}

func (service *SpeakerIdentityService) Enroll(ctx context.Context,
	displayName, recognizedID string, packets [][]byte) (SpeakerMatch, error) {
	return service.enroll(ctx, displayName, recognizedID, false, packets)
}

// EnrollWithPhysicalConfirmation may add a sample to an existing display name
// even when the current short utterance did not clear the recognition
// threshold. Callers must invoke it only after explicit physical consent.
func (service *SpeakerIdentityService) EnrollWithPhysicalConfirmation(
	ctx context.Context, displayName, recognizedID string,
	packets [][]byte) (SpeakerMatch, error) {
	return service.enroll(ctx, displayName, recognizedID, true, packets)
}

func (service *SpeakerIdentityService) enroll(ctx context.Context,
	displayName, recognizedID string, allowConfirmedNameMatch bool,
	packets [][]byte) (SpeakerMatch, error) {
	displayName = strings.TrimSpace(displayName)
	if !validSpeakerDisplayName(displayName) {
		return SpeakerMatch{}, fmt.Errorf("speaker display name is invalid")
	}
	embedding, err := service.embedder.Embed(ctx, packets)
	if err != nil {
		return SpeakerMatch{}, err
	}
	now := time.Now().UTC()
	service.mu.Lock()
	defer service.mu.Unlock()
	var profile speakerProfile
	if recognizedID != "" {
		var found bool
		profile, found = service.profiles[recognizedID]
		if !found {
			return SpeakerMatch{}, fmt.Errorf("recognized speaker profile is unavailable")
		}
		profile.DisplayName = displayName
	} else {
		matchedExistingName := false
		for _, existing := range service.profiles {
			if strings.EqualFold(existing.DisplayName, displayName) {
				if !allowConfirmedNameMatch {
					return SpeakerMatch{}, fmt.Errorf("that speaker name is already enrolled")
				}
				profile = existing
				matchedExistingName = true
				break
			}
		}
		if !matchedExistingName && len(service.profiles) >= maximumSpeakerProfiles {
			return SpeakerMatch{}, fmt.Errorf("speaker profile capacity reached")
		}
		if !matchedExistingName {
			profileID, idErr := newSpeakerProfileID()
			if idErr != nil {
				return SpeakerMatch{}, idErr
			}
			profile = speakerProfile{
				ID: profileID, DisplayName: displayName, CreatedAt: now,
			}
		}
	}
	profile.Embeddings = append(profile.Embeddings, embedding)
	if len(profile.Embeddings) > maximumSpeakerEnrollmentSamples {
		profile.Embeddings = append([][]float32(nil),
			profile.Embeddings[len(profile.Embeddings)-maximumSpeakerEnrollmentSamples:]...)
	}
	profile.UpdatedAt = now
	previous, existed := service.profiles[profile.ID]
	service.profiles[profile.ID] = profile
	if err := service.persistLocked(); err != nil {
		if existed {
			service.profiles[profile.ID] = previous
		} else {
			delete(service.profiles, profile.ID)
		}
		return SpeakerMatch{}, err
	}
	return SpeakerMatch{
		ID: profile.ID, DisplayName: profile.DisplayName,
		Similarity: 1, Known: true,
	}, nil
}

func (service *SpeakerIdentityService) Forget(profileID string) (bool, error) {
	if service == nil || !validMemoryOwner(profileID) || profileID == "" {
		return false, fmt.Errorf("speaker profile is invalid")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	profile, found := service.profiles[profileID]
	if !found {
		return false, nil
	}
	delete(service.profiles, profileID)
	if err := service.persistLocked(); err != nil {
		service.profiles[profileID] = profile
		return false, err
	}
	return true, nil
}

func validSpeakerDisplayName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 24 {
		return false
	}
	letters := 0
	for _, character := range name {
		if unicode.IsLetter(character) {
			letters++
			continue
		}
		if unicode.IsDigit(character) || unicode.IsSpace(character) ||
			character == '-' || character == '_' || character == '·' {
			continue
		}
		return false
	}
	return letters > 0
}

func newSpeakerProfileID() (string, error) {
	value := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", fmt.Errorf("generate speaker profile ID: %w", err)
	}
	return "spk-" + hex.EncodeToString(value), nil
}

func normalizeSpeakerEmbedding(vector []float32) ([]float32, error) {
	if len(vector) == 0 || len(vector) > maximumSpeakerEmbeddingDimension {
		return nil, fmt.Errorf("speaker embedding dimension is invalid")
	}
	normSquared := 0.0
	for _, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return nil, fmt.Errorf("speaker embedding contains a non-finite value")
		}
		normSquared += float64(value) * float64(value)
	}
	if normSquared < 1e-12 {
		return nil, fmt.Errorf("speaker embedding has zero norm")
	}
	norm := float32(math.Sqrt(normSquared))
	result := make([]float32, len(vector))
	for index, value := range vector {
		result[index] = value / norm
	}
	return result, nil
}

func averageSpeakerEmbeddings(embeddings [][]float32) ([]float32, error) {
	if len(embeddings) == 0 {
		return nil, fmt.Errorf("speaker profile has no embeddings")
	}
	dimension := len(embeddings[0])
	average := make([]float32, dimension)
	for _, embedding := range embeddings {
		if len(embedding) != dimension {
			return nil, fmt.Errorf("speaker profile embedding dimensions differ")
		}
		for index, value := range embedding {
			average[index] += value
		}
	}
	return normalizeSpeakerEmbedding(average)
}

func speakerCosineSimilarity(left, right []float32) float64 {
	if len(left) == 0 || len(left) != len(right) {
		return -1
	}
	dot := 0.0
	for index := range left {
		dot += float64(left[index]) * float64(right[index])
	}
	return dot
}

func (service *SpeakerIdentityService) load() error {
	data, err := os.ReadFile(service.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read encrypted speaker identities: %w", err)
	}
	if len(data) < len(speakerIdentityFileHeader)+service.aead.NonceSize() ||
		string(data[:len(speakerIdentityFileHeader)]) != speakerIdentityFileHeader {
		return fmt.Errorf("encrypted speaker identity file has an invalid format")
	}
	nonceStart := len(speakerIdentityFileHeader)
	nonceEnd := nonceStart + service.aead.NonceSize()
	plain, err := service.aead.Open(nil, data[nonceStart:nonceEnd], data[nonceEnd:],
		[]byte(speakerIdentityFileHeader))
	if err != nil {
		return fmt.Errorf("authenticate encrypted speaker identities: %w", err)
	}
	var profiles []speakerProfile
	if err := json.Unmarshal(plain, &profiles); err != nil ||
		len(profiles) > maximumSpeakerProfiles {
		return fmt.Errorf("encrypted speaker identity content is invalid")
	}
	for _, profile := range profiles {
		if !validMemoryOwner(profile.ID) || profile.ID == "" ||
			!validSpeakerDisplayName(profile.DisplayName) ||
			len(profile.Embeddings) == 0 ||
			len(profile.Embeddings) > maximumSpeakerEnrollmentSamples {
			return fmt.Errorf("encrypted speaker profile is invalid")
		}
		for index, embedding := range profile.Embeddings {
			normalized, normalizeErr := normalizeSpeakerEmbedding(embedding)
			if normalizeErr != nil {
				return fmt.Errorf("encrypted speaker embedding is invalid")
			}
			profile.Embeddings[index] = normalized
		}
		if _, duplicate := service.profiles[profile.ID]; duplicate {
			return fmt.Errorf("encrypted speaker identity contains a duplicate")
		}
		service.profiles[profile.ID] = profile
	}
	return nil
}

func (service *SpeakerIdentityService) persistLocked() error {
	if service.path == "" {
		return nil
	}
	profiles := make([]speakerProfile, 0, len(service.profiles))
	for _, profile := range service.profiles {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	plain, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	nonce := make([]byte, service.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate speaker identity nonce: %w", err)
	}
	data := append([]byte(speakerIdentityFileHeader), nonce...)
	data = service.aead.Seal(data, nonce, plain, []byte(speakerIdentityFileHeader))
	directory := filepath.Dir(service.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create speaker identity directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".speaker-identities-*")
	if err != nil {
		return fmt.Errorf("create speaker identity snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write encrypted speaker identities: %w", err)
	}
	if err := os.Rename(temporaryPath, service.path); err != nil {
		return fmt.Errorf("commit encrypted speaker identities: %w", err)
	}
	return nil
}
