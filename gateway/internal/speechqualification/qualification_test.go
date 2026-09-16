package speechqualification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	voicegateway "xiaozhi-agent-platform/gateway/internal/gateway"
	"xiaozhi-agent-platform/gateway/internal/opuspacket"
	"xiaozhi-agent-platform/gateway/internal/speechcontract"
	"xiaozhi-agent-platform/gateway/internal/tts"
)

const (
	testCorpusName  = "../../testdata/speech/adapter-harness-corpus.json"
	testFixtures    = "../../testdata/speech/opus-codec-fixtures.json"
	testCandidate   = "../../testdata/speech/adapter-harness-candidate.json"
	testBearerToken = "qualification-secret"
)

type fakeDecoder struct{}

func (fakeDecoder) Identity() DecoderIdentity {
	return DecoderIdentity{
		FixtureManifestSHA256: strings.Repeat("1", 64),
		FFmpegSHA256:          strings.Repeat("2", 64),
		FFmpegVersion:         "test decoder",
	}
}

func (fakeDecoder) Decode(_ context.Context, packet []byte, sampleRate int) (DecodeResult, error) {
	if err := opuspacket.ValidateMonoDuration(packet, 60); err != nil {
		return DecodeResult{}, err
	}
	digest := sha256.Sum256(append(append([]byte{}, packet...), byte(sampleRate), byte(sampleRate>>8)))
	return DecodeResult{
		Samples: sampleRate * 60 / 1000, PCMHash: hex.EncodeToString(digest[:]), NonSilent: true,
	}, nil
}

type harnessState struct {
	t              *testing.T
	corpus         LoadedCorpus
	ttsPacket      []byte
	normalSTT      atomic.Int32
	abortedSTT     atomic.Int32
	ttsRequests    atomic.Int32
	cancelRequests atomic.Int32
}

func newHarnessServer(t *testing.T, corpus LoadedCorpus) (*httptest.Server, *harnessState) {
	t.Helper()
	fixtureData, err := os.ReadFile(testFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var manifest codecFixtureManifest
	if err := json.Unmarshal(fixtureData, &manifest); err != nil {
		t.Fatal(err)
	}
	var ttsPacket []byte
	for _, fixture := range manifest.Fixtures {
		if fixture.Name == "tts-24k-mono-60ms" {
			ttsPacket, err = base64.StdEncoding.Strict().DecodeString(fixture.Packet)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(ttsPacket) == 0 {
		t.Fatal("missing TTS fixture")
	}
	state := &harnessState{t: t, corpus: corpus, ttsPacket: ttsPacket}
	server := httptest.NewServer(http.HandlerFunc(state.handle))
	return server, state
}

func (state *harnessState) handle(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+testBearerToken {
		state.t.Error("missing adapter authorization")
	}
	switch request.URL.Path {
	case "/stt-health":
		if request.Header.Get(speechcontract.Header) != speechcontract.STTVersion {
			state.t.Error("wrong STT readiness contract")
		}
		writer.Header().Set(speechcontract.Header, speechcontract.STTVersion)
		writer.WriteHeader(http.StatusNoContent)
	case "/tts-health":
		if request.Header.Get(speechcontract.Header) != speechcontract.TTSVersion {
			state.t.Error("wrong TTS readiness contract")
		}
		writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
		writer.WriteHeader(http.StatusNoContent)
	case "/stt":
		state.handleSTT(writer, request)
	case "/tts":
		state.handleTTS(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (state *harnessState) handleSTT(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get(speechcontract.Header) != speechcontract.STTVersion {
		state.t.Error("wrong live STT contract")
	}
	writer.Header().Set(speechcontract.Header, speechcontract.STTVersion)
	socket, err := websocket.Accept(writer, request, nil)
	if err != nil {
		state.t.Error(err)
		return
	}
	defer socket.CloseNow()
	messageType, payload, err := socket.Read(request.Context())
	if err != nil || messageType != websocket.MessageText {
		state.t.Errorf("invalid STT start: %v", err)
		return
	}
	var start struct {
		Type      string `json:"type"`
		Contract  string `json:"contract"`
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(payload, &start) != nil || start.Type != "start" ||
		start.Contract != speechcontract.STTVersion {
		state.t.Error("invalid STT start payload")
		return
	}
	if strings.HasSuffix(start.SessionID, ":abort") {
		messageType, payload, err = socket.Read(request.Context())
		if err != nil || messageType != websocket.MessageText || !bytesContains(payload, `"type":"abort"`) {
			state.t.Error("invalid STT abort payload")
			return
		}
		state.abortedSTT.Add(1)
		<-request.Context().Done()
		return
	}
	for _, expected := range state.corpus.STT {
		messageType, payload, err = socket.Read(request.Context())
		if err != nil || messageType != websocket.MessageBinary || string(payload) != string(expected) {
			state.t.Error("invalid STT fixture packet")
			return
		}
	}
	messageType, payload, err = socket.Read(request.Context())
	if err != nil || messageType != websocket.MessageText || !bytesContains(payload, `"state":"stop"`) {
		state.t.Error("invalid STT stop payload")
		return
	}
	response, _ := json.Marshal(map[string]any{
		"type": "stt", "text": state.corpus.Corpus.STT.ExpectedText, "final": true,
	})
	if err := socket.Write(request.Context(), websocket.MessageText, response); err != nil {
		state.t.Error(err)
		return
	}
	state.normalSTT.Add(1)
	<-request.Context().Done()
}

func (state *harnessState) handleTTS(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get(speechcontract.Header) != speechcontract.TTSVersion ||
		request.Header.Get("Idempotency-Key") == "" {
		state.t.Error("wrong TTS contract or idempotency key")
	}
	var body struct {
		Contract  string `json:"contract"`
		RequestID uint32 `json:"request_id"`
		Text      string `json:"text"`
	}
	if json.NewDecoder(request.Body).Decode(&body) != nil || body.Contract != speechcontract.TTSVersion {
		state.t.Error("invalid TTS request")
		return
	}
	frames := 1
	switch body.Text {
	case state.corpus.Corpus.TTS[0].Text:
		frames = 1
	case state.corpus.Corpus.TTS[1].Text:
		frames = 2
	case state.corpus.Corpus.Cancel.Text:
		frames = 3
		state.cancelRequests.Add(1)
	default:
		state.t.Error("unexpected TTS qualification text")
		return
	}
	state.ttsRequests.Add(1)
	writer.Header().Set("Content-Type", "application/x-opus-frames")
	writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
	for range frames {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(state.ttsPacket)))
		_, _ = writer.Write(size[:])
		_, _ = writer.Write(state.ttsPacket)
	}
}

func runHarness(t *testing.T, decoder PacketDecoder) (Receipt, LoadedCorpus, *harnessState) {
	t.Helper()
	corpus, err := LoadCorpus(testCorpusName)
	if err != nil {
		t.Fatal(err)
	}
	server, state := newHarnessServer(t, corpus)
	t.Cleanup(server.Close)
	voice, err := voicegateway.NewWebSocketSTT(voicegateway.WebSocketSTTConfig{
		Endpoint:  "ws" + strings.TrimPrefix(server.URL, "http") + "/stt",
		HealthURL: server.URL + "/stt-health", BearerToken: testBearerToken,
		HTTPClient: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	synthesizer, err := tts.NewFramedHTTP(tts.FramedHTTPConfig{
		Endpoint: server.URL + "/tts", HealthURL: server.URL + "/tts-health",
		BearerToken: testBearerToken, Client: server.Client(), AllowInsecure: true,
		SampleRate: 24000, FrameDuration: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	configHash, err := DigestRegularFile(testCandidate, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	receipt, err := (Runner{Voice: voice, TTS: synthesizer, Decoder: decoder}).Run(
		ctx, corpus, ProbeMetadata{
			RunID: "m28-test-run", CandidateID: "m28-local-test-double",
			CandidateConfigSHA256: configHash, CorpusSHA256: corpus.SHA256,
			AdapterEndpointSetSHA256: EndpointSetDigest(
				server.URL+"/stt", server.URL+"/stt-health",
				server.URL+"/tts", server.URL+"/tts-health"),
			QualificationToolSHA256: strings.Repeat("3", 64),
			TransportTrustSHA256:    TransportTrustDigest(""),
			ConsentClass:            corpus.Corpus.ConsentClass, DevelopmentOnly: true,
			Thresholds: Thresholds{
				MaxSTTFinalMS: 500, MaxTTSFirstFrameMS: 500,
				MaxTTSCompleteMS: 1000, MaxCancelReturnMS: 25,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, corpus, state
}

func TestRunnerExercisesContractIsolationCancellationAndTranscriptFreeEvidence(t *testing.T) {
	receipt, _, state := runHarness(t, fakeDecoder{})
	if receipt.QualificationStatus != "TEST_HARNESS_PASS" || receipt.ProductionReady ||
		len(receipt.TTS) != 2 || receipt.Cancel.FramesBeforeCancel != 1 ||
		!receipt.STT.TranscriptExactMatch {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	data, err := prettyJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), state.corpus.Corpus.STT.ExpectedText) ||
		strings.Contains(string(data), state.corpus.Corpus.TTS[0].Text) {
		t.Fatal("qualification receipt leaked transcript or synthesis text")
	}
	if state.normalSTT.Load() != 1 || state.abortedSTT.Load() != 1 ||
		state.ttsRequests.Load() != 3 || state.cancelRequests.Load() != 1 {
		t.Fatalf("harness paths missing: stt=%d abort=%d tts=%d cancel=%d",
			state.normalSTT.Load(), state.abortedSTT.Load(),
			state.ttsRequests.Load(), state.cancelRequests.Load())
	}
}

func TestSignedReceiptRejectsTamperAndDevelopmentPromotion(t *testing.T) {
	receipt, _, _ := runHarness(t, fakeDecoder{})
	privateName, publicName := writeTestKeys(t)
	signed, err := SignReceipt(receipt, privateName, "speech-qualification-test-key")
	if err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{
		TrustedPublicKey: publicName, ExpectedSigningKeyID: "speech-qualification-test-key",
		ExpectedRunID: receipt.RunID, ExpectedCandidateID: receipt.CandidateID,
		ExpectedCandidateConfig:   receipt.CandidateConfigSHA256,
		ExpectedEndpointSet:       receipt.AdapterEndpointSetSHA256,
		ExpectedQualificationTool: receipt.QualificationToolSHA256,
		ExpectedTransportTrust:    receipt.TransportTrustSHA256,
		ExpectedCorpusSHA256:      receipt.CorpusSHA256, ExpectedConsentClass: receipt.ConsentClass,
		ExpectedFixtureManifest: receipt.Codec.FixtureManifestSHA256,
		ExpectedFFmpegSHA256:    receipt.Codec.FFmpegSHA256,
		ExpectedThresholds:      receipt.Thresholds, RequireExpectedThresholds: true,
	}
	if _, err := VerifyReceipt(signed, options); err != nil {
		t.Fatal(err)
	}
	wrongEndpoint := options
	wrongEndpoint.ExpectedEndpointSet = strings.Repeat("f", 64)
	if _, err := VerifyReceipt(signed, wrongEndpoint); err == nil {
		t.Fatal("receipt was accepted for a different tested endpoint set")
	}
	wrongTrust := options
	wrongTrust.ExpectedTransportTrust = strings.Repeat("e", 64)
	if _, err := VerifyReceipt(signed, wrongTrust); err == nil {
		t.Fatal("receipt was accepted for a different transport trust policy")
	}
	wrongThresholds := options
	wrongThresholds.ExpectedThresholds.MaxSTTFinalMS++
	if _, err := VerifyReceipt(signed, wrongThresholds); err == nil {
		t.Fatal("receipt was accepted against different frozen thresholds")
	}
	production := options
	production.RequireProductionTransport = true
	if _, err := VerifyReceipt(signed, production); err == nil {
		t.Fatal("development receipt was accepted as production transport evidence")
	}
	var tampered Receipt
	if err := json.Unmarshal(signed, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.ReadinessMS++
	tamperedData, _ := prettyJSON(tampered)
	if _, err := VerifyReceipt(tamperedData, options); err == nil {
		t.Fatal("tampered signed receipt was accepted")
	}
	if err := os.Chmod(privateName, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SignReceipt(receipt, privateName, "speech-qualification-test-key"); err == nil {
		t.Fatal("world-readable qualification private key was accepted")
	}
	output := filepath.Join(t.TempDir(), "receipt.json")
	if err := WriteNewReceipt(output, signed); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewReceipt(output, signed); err == nil {
		t.Fatal("qualification receipt overwrite was accepted")
	}
}

func TestLiveHarnessWithPinnedReferenceDecoder(t *testing.T) {
	ffmpeg := os.Getenv("XIAOZHI_FFMPEG")
	if ffmpeg == "" {
		t.Skip("XIAOZHI_FFMPEG is not set")
	}
	decoder, err := NewReferenceDecoder(ffmpeg, testFixtures)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _, _ := runHarness(t, decoder)
	if receipt.Codec.FFmpegSHA256 != "326895b16940f238d76e902fc71150f10c388c281985756f9850ff800a2f1499" {
		t.Fatal("live harness used the wrong decoder")
	}
	privateName, publicName := writeTestKeys(t)
	signed, err := SignReceipt(receipt, privateName, "m28-live-harness-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(signed, VerifyOptions{
		TrustedPublicKey: publicName, ExpectedSigningKeyID: "m28-live-harness-key",
		ExpectedRunID: receipt.RunID, ExpectedCandidateID: receipt.CandidateID,
		ExpectedCandidateConfig:   receipt.CandidateConfigSHA256,
		ExpectedEndpointSet:       receipt.AdapterEndpointSetSHA256,
		ExpectedQualificationTool: receipt.QualificationToolSHA256,
		ExpectedTransportTrust:    receipt.TransportTrustSHA256,
		ExpectedCorpusSHA256:      receipt.CorpusSHA256, ExpectedConsentClass: receipt.ConsentClass,
		ExpectedFixtureManifest: receipt.Codec.FixtureManifestSHA256,
		ExpectedFFmpegSHA256:    receipt.Codec.FFmpegSHA256,
		ExpectedThresholds:      receipt.Thresholds, RequireExpectedThresholds: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCorpusRejectsNoncanonicalAndWrongConsent(t *testing.T) {
	data, err := os.ReadFile(testCorpusName)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	noncanonical := filepath.Join(directory, "noncanonical.json")
	if err := os.WriteFile(noncanonical, append([]byte(" "), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpus(noncanonical); err == nil {
		t.Fatal("noncanonical corpus was accepted")
	}
	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	corpus.ConsentClass = "unreviewed"
	wrongConsent := filepath.Join(directory, "wrong-consent.json")
	wrongData, _ := prettyJSON(corpus)
	if err := os.WriteFile(wrongConsent, wrongData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpus(wrongConsent); err == nil {
		t.Fatal("unreviewed corpus consent class was accepted")
	}
}

func writeTestKeys(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	privateName := filepath.Join(directory, "private.pem")
	publicName := filepath.Join(directory, "public.pem")
	if err := os.WriteFile(privateName, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicName, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o444); err != nil {
		t.Fatal(err)
	}
	return privateName, publicName
}

func bytesContains(payload []byte, value string) bool {
	return strings.Contains(string(payload), value)
}
