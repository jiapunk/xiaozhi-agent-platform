package speechqualification

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	voicegateway "xiaozhi-agent-platform/gateway/internal/gateway"
	"xiaozhi-agent-platform/gateway/internal/tts"
)

const ReceiptSchema = "xiaozhi-speech-adapter-qualification-v1"

var requiredUnresolvedGates = []string{
	"BOX3 ESP codec and acoustic canary",
	"current privacy legal retention and DPA review",
	"human Mandarin and code-switching quality scoring",
	"load failure quota cost and soak evidence",
	"production workload identity secret rotation and HA deployment",
}

type Thresholds struct {
	MaxSTTFinalMS      int64 `json:"max_stt_final_ms"`
	MaxTTSFirstFrameMS int64 `json:"max_tts_first_frame_ms"`
	MaxTTSCompleteMS   int64 `json:"max_tts_complete_ms"`
	MaxCancelReturnMS  int64 `json:"max_cancel_return_ms"`
}

type ProbeMetadata struct {
	RunID                    string
	CandidateID              string
	CandidateConfigSHA256    string
	AdapterEndpointSetSHA256 string
	QualificationToolSHA256  string
	TransportTrustSHA256     string
	CorpusSHA256             string
	ConsentClass             string
	DevelopmentOnly          bool
	Thresholds               Thresholds
}

type STTResult struct {
	CaseID                  string `json:"case_id"`
	InputPackets            int    `json:"input_packets"`
	InputDurationMS         int    `json:"input_duration_ms"`
	InputPacketStreamSHA256 string `json:"input_packet_stream_sha256"`
	DecodedPCMSetSHA256     string `json:"decoded_pcm_set_sha256"`
	TranscriptExactMatch    bool   `json:"transcript_exact_match"`
	SingleFinalObserved     bool   `json:"single_final_observed"`
	FinalAfterStopMS        int64  `json:"final_after_stop_ms"`
	AbortNoFinalObserved    bool   `json:"abort_no_final_observed"`
	AbortObservationMS      int64  `json:"abort_observation_ms"`
}

type TTSResult struct {
	CaseID              string `json:"case_id"`
	RequestID           uint32 `json:"request_id"`
	Frames              int    `json:"frames"`
	DecodedSamples      int    `json:"decoded_samples"`
	PacketStreamSHA256  string `json:"packet_stream_sha256"`
	DecodedPCMSetSHA256 string `json:"decoded_pcm_set_sha256"`
	FirstFrameMS        int64  `json:"first_frame_ms"`
	CompleteMS          int64  `json:"complete_ms"`
	EveryFrameNonSilent bool   `json:"every_frame_non_silent"`
}

type CancelResult struct {
	CaseID                string `json:"case_id"`
	RequestID             uint32 `json:"request_id"`
	FramesBeforeCancel    int    `json:"frames_before_cancel"`
	CancelToReturnMS      int64  `json:"cancel_to_return_ms"`
	ReturnedContextCancel bool   `json:"returned_context_cancel"`
}

type Receipt struct {
	Schema                    string          `json:"schema"`
	RunID                     string          `json:"run_id"`
	CandidateID               string          `json:"candidate_id"`
	CandidateConfigSHA256     string          `json:"candidate_config_sha256"`
	AdapterEndpointSetSHA256  string          `json:"adapter_endpoint_set_sha256"`
	QualificationToolSHA256   string          `json:"qualification_tool_sha256"`
	TransportTrustSHA256      string          `json:"transport_trust_sha256"`
	CorpusSHA256              string          `json:"corpus_sha256"`
	ConsentClass              string          `json:"consent_class"`
	Codec                     DecoderIdentity `json:"reference_codec"`
	StartedAtUnixMS           int64           `json:"started_at_unix_ms"`
	CompletedAtUnixMS         int64           `json:"completed_at_unix_ms"`
	DevelopmentOnly           bool            `json:"development_only"`
	Thresholds                Thresholds      `json:"thresholds"`
	ReadinessMS               int64           `json:"readiness_ms"`
	STT                       STTResult       `json:"stt"`
	TTS                       []TTSResult     `json:"tts"`
	Cancel                    CancelResult    `json:"tts_cancel"`
	QualificationStatus       string          `json:"qualification_status"`
	ProductionReady           bool            `json:"production_ready"`
	UnresolvedProductionGates []string        `json:"unresolved_production_gates"`
	SigningKeyID              string          `json:"signing_key_id"`
	SignatureAlgorithm        string          `json:"signature_algorithm"`
	SignatureB64URL           string          `json:"signature_b64url,omitempty"`
}

type Runner struct {
	Voice   voicegateway.VoiceBackend
	TTS     tts.Synthesizer
	Decoder PacketDecoder
	Now     func() time.Time
}

func (runner Runner) Run(ctx context.Context, loaded LoadedCorpus, metadata ProbeMetadata) (Receipt, error) {
	if runner.Voice == nil || runner.TTS == nil || runner.Decoder == nil {
		return Receipt{}, fmt.Errorf("speech qualification dependencies are incomplete")
	}
	if runner.Now == nil {
		runner.Now = time.Now
	}
	if err := validateMetadata(metadata, loaded); err != nil {
		return Receipt{}, err
	}
	started := runner.Now()
	receipt := Receipt{
		Schema: ReceiptSchema, RunID: metadata.RunID, CandidateID: metadata.CandidateID,
		CandidateConfigSHA256:    metadata.CandidateConfigSHA256,
		AdapterEndpointSetSHA256: metadata.AdapterEndpointSetSHA256,
		QualificationToolSHA256:  metadata.QualificationToolSHA256,
		TransportTrustSHA256:     metadata.TransportTrustSHA256,
		CorpusSHA256:             metadata.CorpusSHA256, ConsentClass: metadata.ConsentClass,
		Codec: runner.Decoder.Identity(), StartedAtUnixMS: started.UnixMilli(),
		DevelopmentOnly: metadata.DevelopmentOnly, Thresholds: metadata.Thresholds,
		ProductionReady:           false,
		UnresolvedProductionGates: append([]string(nil), requiredUnresolvedGates...),
	}

	sttPacketHash := sha256.New()
	sttPCMHash := sha256.New()
	for _, packet := range loaded.STT {
		writeFramedHash(sttPacketHash, packet)
		decoded, err := runner.Decoder.Decode(ctx, packet, 16000)
		if err != nil || decoded.Samples != 960 || !decoded.NonSilent ||
			stringsLowerHex(decoded.PCMHash) == "" {
			return Receipt{}, fmt.Errorf("STT corpus reference decode failed")
		}
		writeHexDigest(sttPCMHash, decoded.PCMHash)
	}

	readyStarted := runner.Now()
	if err := runner.Voice.Ready(ctx); err != nil {
		return Receipt{}, fmt.Errorf("STT readiness: %w", err)
	}
	if err := runner.TTS.Ready(ctx); err != nil {
		return Receipt{}, fmt.Errorf("TTS readiness: %w", err)
	}
	receipt.ReadinessMS = elapsedMillis(readyStarted, runner.Now())

	sttResult, err := runner.runSTT(ctx, loaded, metadata)
	if err != nil {
		return Receipt{}, err
	}
	sttResult.InputPacketStreamSHA256 = hex.EncodeToString(sttPacketHash.Sum(nil))
	sttResult.DecodedPCMSetSHA256 = hex.EncodeToString(sttPCMHash.Sum(nil))
	receipt.STT = sttResult

	ttsResults, err := runner.runTTS(ctx, loaded.Corpus.TTS, metadata.Thresholds)
	if err != nil {
		return Receipt{}, err
	}
	receipt.TTS = ttsResults
	cancelResult, err := runner.runCancel(ctx, loaded.Corpus.Cancel, metadata.Thresholds)
	if err != nil {
		return Receipt{}, err
	}
	receipt.Cancel = cancelResult
	receipt.CompletedAtUnixMS = runner.Now().UnixMilli()
	if metadata.DevelopmentOnly {
		receipt.QualificationStatus = "TEST_HARNESS_PASS"
	} else {
		receipt.QualificationStatus = "PROTOCOL_PASS"
	}
	return receipt, nil
}

func validateMetadata(metadata ProbeMetadata, loaded LoadedCorpus) error {
	if !validIdentifier(metadata.RunID) || !validIdentifier(metadata.CandidateID) ||
		len(metadata.CandidateConfigSHA256) != 64 ||
		metadata.CandidateConfigSHA256 != stringsLowerHex(metadata.CandidateConfigSHA256) ||
		stringsLowerHex(metadata.AdapterEndpointSetSHA256) == "" ||
		stringsLowerHex(metadata.QualificationToolSHA256) == "" ||
		stringsLowerHex(metadata.TransportTrustSHA256) == "" ||
		metadata.CorpusSHA256 != loaded.SHA256 || metadata.ConsentClass != loaded.Corpus.ConsentClass {
		return fmt.Errorf("speech qualification metadata is invalid")
	}
	thresholds := metadata.Thresholds
	if thresholds.MaxSTTFinalMS < 1 || thresholds.MaxSTTFinalMS > 60000 ||
		thresholds.MaxTTSFirstFrameMS < 1 || thresholds.MaxTTSFirstFrameMS > 60000 ||
		thresholds.MaxTTSCompleteMS < thresholds.MaxTTSFirstFrameMS ||
		thresholds.MaxTTSCompleteMS > 120000 || thresholds.MaxCancelReturnMS < 1 ||
		thresholds.MaxCancelReturnMS > 10000 || !sortedStrings(requiredUnresolvedGates) {
		return fmt.Errorf("speech qualification thresholds are invalid")
	}
	return nil
}

func EndpointSetDigest(sttURL, sttHealthURL, ttsURL, ttsHealthURL string) string {
	return hashBytes([]byte(
		"XIAOZHI-SPEECH-ADAPTER-ENDPOINTS-V1\x00" +
			"stt=" + sttURL + "\n" +
			"stt_health=" + sttHealthURL + "\n" +
			"tts=" + ttsURL + "\n" +
			"tts_health=" + ttsHealthURL + "\n",
	))
}

func TransportTrustDigest(caBundleSHA256 string) string {
	if caBundleSHA256 == "" {
		return hashBytes([]byte("XIAOZHI-SPEECH-SYSTEM-TRUST-V1\x00"))
	}
	if stringsLowerHex(caBundleSHA256) == "" {
		return ""
	}
	return hashBytes([]byte("XIAOZHI-SPEECH-PRIVATE-CA-V1\x00" + caBundleSHA256))
}

type qualificationEmitter struct {
	stt      chan string
	failures chan error
}

func (emitter *qualificationEmitter) SendSTT(_ context.Context, text string) error {
	select {
	case emitter.stt <- text:
		return nil
	default:
		return fmt.Errorf("qualification STT emitted too many final events")
	}
}

func (*qualificationEmitter) SendJSON(context.Context, []byte) error { return nil }

func (emitter *qualificationEmitter) FailVoice(cause error) {
	select {
	case emitter.failures <- cause:
	default:
	}
}

func (runner Runner) runSTT(ctx context.Context, loaded LoadedCorpus, metadata ProbeMetadata) (STTResult, error) {
	corpus := loaded.Corpus
	sessionID := "qualify:" + metadata.RunID
	emitter := &qualificationEmitter{stt: make(chan string, 2), failures: make(chan error, 2)}
	session, err := runner.Voice.Open(ctx, voicegateway.VoiceSessionConfig{
		DeviceID: "qualification-device", ClientID: metadata.RunID, SessionID: sessionID,
		SampleRate: 16000, FrameDuration: 60, ProtocolVersion: 1,
	}, emitter)
	if err != nil {
		return STTResult{}, fmt.Errorf("open STT qualification session: %w", err)
	}
	defer session.Close()
	for _, packet := range loaded.STT {
		if err := session.HandleAudio(ctx, packet); err != nil {
			return STTResult{}, fmt.Errorf("send STT qualification audio: %w", err)
		}
	}
	stop, _ := json.Marshal(map[string]any{
		"type": "listen", "session_id": sessionID, "state": "stop",
	})
	stopAt := runner.Now()
	if err := session.HandleControl(ctx, stop); err != nil {
		return STTResult{}, fmt.Errorf("stop STT qualification session: %w", err)
	}
	waitContext, cancel := context.WithTimeout(ctx, time.Duration(metadata.Thresholds.MaxSTTFinalMS)*time.Millisecond)
	defer cancel()
	var observed string
	select {
	case observed = <-emitter.stt:
	case failure := <-emitter.failures:
		return STTResult{}, fmt.Errorf("STT adapter failed: %w", failure)
	case <-waitContext.Done():
		return STTResult{}, fmt.Errorf("STT final exceeded frozen threshold")
	}
	finalMS := elapsedMillis(stopAt, runner.Now())
	if observed != corpus.STT.ExpectedText {
		return STTResult{}, fmt.Errorf("STT output differs from approved corpus transcript")
	}
	duplicateWindow := time.Duration(metadata.Thresholds.MaxCancelReturnMS) * time.Millisecond
	if duplicateWindow > 250*time.Millisecond {
		duplicateWindow = 250 * time.Millisecond
	}
	duplicateTimer := time.NewTimer(duplicateWindow)
	defer duplicateTimer.Stop()
	select {
	case <-emitter.stt:
		return STTResult{}, fmt.Errorf("STT adapter emitted more than one final event")
	case failure := <-emitter.failures:
		return STTResult{}, fmt.Errorf("STT adapter failed after final: %w", failure)
	case <-ctx.Done():
		return STTResult{}, ctx.Err()
	case <-duplicateTimer.C:
	}
	if err := session.Close(); err != nil {
		return STTResult{}, fmt.Errorf("close STT qualification session: %w", err)
	}
	abortObserved, abortMS, err := runner.runSTTAbort(ctx, loaded, metadata)
	if err != nil {
		return STTResult{}, err
	}
	return STTResult{
		CaseID: corpus.STT.CaseID, InputPackets: len(loaded.STT),
		InputDurationMS:      len(loaded.STT) * 60,
		TranscriptExactMatch: true, SingleFinalObserved: true, FinalAfterStopMS: finalMS,
		AbortNoFinalObserved: abortObserved, AbortObservationMS: abortMS,
	}, nil
}

func (runner Runner) runSTTAbort(ctx context.Context, loaded LoadedCorpus, metadata ProbeMetadata) (bool, int64, error) {
	sessionID := "qualify:" + metadata.RunID + ":abort"
	emitter := &qualificationEmitter{stt: make(chan string, 1), failures: make(chan error, 1)}
	session, err := runner.Voice.Open(ctx, voicegateway.VoiceSessionConfig{
		DeviceID: "qualification-device", ClientID: metadata.RunID, SessionID: sessionID,
		SampleRate: 16000, FrameDuration: 60, ProtocolVersion: 1,
	}, emitter)
	if err != nil {
		return false, 0, fmt.Errorf("open STT abort session: %w", err)
	}
	defer session.Close()
	abort, _ := json.Marshal(map[string]any{
		"type": "abort", "session_id": sessionID, "reason": "qualification",
	})
	abortAt := runner.Now()
	if err := session.HandleControl(ctx, abort); err != nil {
		return false, 0, fmt.Errorf("send STT abort: %w", err)
	}
	timer := time.NewTimer(time.Duration(metadata.Thresholds.MaxCancelReturnMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-emitter.stt:
		return false, elapsedMillis(abortAt, runner.Now()), fmt.Errorf("STT emitted a final event after abort")
	case failure := <-emitter.failures:
		return false, elapsedMillis(abortAt, runner.Now()), fmt.Errorf("STT abort session failed: %w", failure)
	case <-ctx.Done():
		return false, 0, ctx.Err()
	case <-timer.C:
		return true, elapsedMillis(abortAt, runner.Now()), nil
	}
}

func (runner Runner) runTTS(ctx context.Context, cases []TTSCase, thresholds Thresholds) ([]TTSResult, error) {
	results := make([]TTSResult, len(cases))
	errorsByCase := make([]error, len(cases))
	var wait sync.WaitGroup
	for index, test := range cases {
		index, test := index, test
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errorsByCase[index] = runner.runTTSCase(ctx, test, uint32(1001+index), thresholds)
		}()
	}
	wait.Wait()
	for index, err := range errorsByCase {
		if err != nil {
			return nil, fmt.Errorf("TTS case %s: %w", cases[index].CaseID, err)
		}
	}
	packetHashes := map[string]bool{}
	pcmHashes := map[string]bool{}
	for _, result := range results {
		packetHashes[result.PacketStreamSHA256] = true
		pcmHashes[result.DecodedPCMSetSHA256] = true
	}
	if len(packetHashes) != len(results) || len(pcmHashes) != len(results) {
		return nil, fmt.Errorf("parallel TTS cases did not produce isolated distinct output")
	}
	sort.Slice(results, func(i, j int) bool { return results[i].CaseID < results[j].CaseID })
	return results, nil
}

func (runner Runner) runTTSCase(ctx context.Context, test TTSCase, requestID uint32, thresholds Thresholds) (TTSResult, error) {
	started := runner.Now()
	packetHash := sha256.New()
	pcmHash := sha256.New()
	frames := 0
	samples := 0
	firstFrameMS := int64(-1)
	err := runner.TTS.Stream(ctx, tts.Request{
		DeviceID: "qualification-device", SessionID: "qualify-tts", RequestID: requestID, Text: test.Text,
	}, func(packet []byte) error {
		if frames >= maximumPackets {
			return fmt.Errorf("qualification TTS frame count exceeded")
		}
		decoded, err := runner.Decoder.Decode(ctx, packet, 24000)
		if err != nil || decoded.Samples != 1440 || !decoded.NonSilent ||
			stringsLowerHex(decoded.PCMHash) == "" {
			return fmt.Errorf("TTS reference decode failed")
		}
		if frames == 0 {
			firstFrameMS = elapsedMillis(started, runner.Now())
		}
		frames++
		samples += decoded.Samples
		writeFramedHash(packetHash, packet)
		writeHexDigest(pcmHash, decoded.PCMHash)
		return nil
	})
	if err != nil {
		return TTSResult{}, err
	}
	completeMS := elapsedMillis(started, runner.Now())
	if frames < 1 || firstFrameMS > thresholds.MaxTTSFirstFrameMS || completeMS > thresholds.MaxTTSCompleteMS {
		return TTSResult{}, fmt.Errorf("TTS latency or frame-count threshold failed")
	}
	return TTSResult{
		CaseID: test.CaseID, RequestID: requestID,
		Frames: frames, DecodedSamples: samples,
		PacketStreamSHA256:  hex.EncodeToString(packetHash.Sum(nil)),
		DecodedPCMSetSHA256: hex.EncodeToString(pcmHash.Sum(nil)),
		FirstFrameMS:        firstFrameMS, CompleteMS: completeMS, EveryFrameNonSilent: true,
	}, nil
}

func (runner Runner) runCancel(ctx context.Context, test TTSCase, thresholds Thresholds) (CancelResult, error) {
	cancelContext, cancel := context.WithCancel(ctx)
	defer cancel()
	frames := 0
	var cancelAt time.Time
	requestID := uint32(9001)
	err := runner.TTS.Stream(cancelContext, tts.Request{
		DeviceID: "qualification-device", SessionID: "qualify-tts-cancel",
		RequestID: requestID, Text: test.Text,
	}, func(packet []byte) error {
		decoded, decodeErr := runner.Decoder.Decode(ctx, packet, 24000)
		if decodeErr != nil || decoded.Samples != 1440 || !decoded.NonSilent ||
			stringsLowerHex(decoded.PCMHash) == "" {
			return fmt.Errorf("TTS cancellation packet failed reference decode")
		}
		frames++
		if frames == 1 {
			cancelAt = runner.Now()
			cancel()
		}
		return nil
	})
	returnedAt := runner.Now()
	if !errors.Is(err, context.Canceled) || frames != 1 || cancelAt.IsZero() {
		return CancelResult{}, fmt.Errorf("TTS cancellation did not fail closed after one frame")
	}
	latency := elapsedMillis(cancelAt, returnedAt)
	if latency > thresholds.MaxCancelReturnMS {
		return CancelResult{}, fmt.Errorf("TTS cancellation exceeded frozen threshold")
	}
	return CancelResult{
		CaseID: test.CaseID, RequestID: requestID,
		FramesBeforeCancel: frames, CancelToReturnMS: latency, ReturnedContextCancel: true,
	}, nil
}

func writeFramedHash(destination interface{ Write([]byte) (int, error) }, payload []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	_, _ = destination.Write(size[:])
	_, _ = destination.Write(payload)
}

func writeHexDigest(destination interface{ Write([]byte) (int, error) }, value string) {
	decoded, _ := hex.DecodeString(value)
	_, _ = destination.Write(decoded)
}

func elapsedMillis(start, end time.Time) int64 {
	value := end.Sub(start).Milliseconds()
	if value < 0 {
		return 0
	}
	return value
}

func stringsLowerHex(value string) string {
	if len(value) != 64 {
		return ""
	}
	nonzero := false
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return ""
		}
		if character != '0' {
			nonzero = true
		}
	}
	if !nonzero {
		return ""
	}
	return value
}
