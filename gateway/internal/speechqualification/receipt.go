package speechqualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"sort"
	"time"
)

var qualificationSignatureDomain = []byte("XIAOZHI-SPEECH-QUALIFICATION-V1\x00")

type VerifyOptions struct {
	TrustedPublicKey           string
	ExpectedSigningKeyID       string
	ExpectedRunID              string
	ExpectedCandidateID        string
	ExpectedCandidateConfig    string
	ExpectedEndpointSet        string
	ExpectedQualificationTool  string
	ExpectedTransportTrust     string
	ExpectedCorpusSHA256       string
	ExpectedConsentClass       string
	ExpectedFixtureManifest    string
	ExpectedFFmpegSHA256       string
	ExpectedThresholds         Thresholds
	RequireExpectedThresholds  bool
	RequireProductionTransport bool
}

func DigestRegularFile(name string, maximum int64) (string, error) {
	data, err := readRegular(name, maximum)
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}

func VerifyReceiptFile(name string, options VerifyOptions) (Receipt, error) {
	data, err := readRegular(name, 1<<20)
	if err != nil {
		return Receipt{}, fmt.Errorf("qualification receipt: %w", err)
	}
	return VerifyReceipt(data, options)
}

func SignReceipt(receipt Receipt, privateKeyName, signingKeyID string) ([]byte, error) {
	if !validIdentifier(signingKeyID) {
		return nil, fmt.Errorf("qualification signing key ID is invalid")
	}
	receipt.SigningKeyID = signingKeyID
	receipt.SignatureAlgorithm = "Ed25519"
	receipt.SignatureB64URL = ""
	if err := validateReceiptFields(receipt, VerifyOptions{ExpectedSigningKeyID: signingKeyID}); err != nil {
		return nil, err
	}
	privateKey, err := loadPrivateKey(privateKeyName)
	if err != nil {
		return nil, err
	}
	payload, err := signaturePayload(receipt)
	if err != nil {
		return nil, err
	}
	receipt.SignatureB64URL = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return prettyJSON(receipt)
}

func VerifyReceipt(data []byte, options VerifyOptions) (Receipt, error) {
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("qualification receipt JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		return receipt, fmt.Errorf("qualification receipt has trailing JSON")
	}
	canonical, err := prettyJSON(receipt)
	if err != nil || !bytes.Equal(canonical, data) {
		return receipt, fmt.Errorf("qualification receipt is not canonical JSON")
	}
	if err := validateReceiptFields(receipt, options); err != nil {
		return receipt, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(receipt.SignatureB64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != receipt.SignatureB64URL {
		return receipt, fmt.Errorf("qualification signature is not canonical base64url")
	}
	publicKey, err := loadPublicKey(options.TrustedPublicKey)
	if err != nil {
		return receipt, err
	}
	payload, err := signaturePayload(receipt)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return receipt, fmt.Errorf("qualification receipt signature is invalid")
	}
	return receipt, nil
}

func WriteNewReceipt(name string, data []byte) error {
	if len(data) < 1 || len(data) > 1<<20 {
		return fmt.Errorf("qualification receipt size is invalid")
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("refusing to overwrite qualification receipt: %w", err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(name)
		}
	}()
	if written, err := file.Write(data); err != nil || written != len(data) {
		return fmt.Errorf("write qualification receipt")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync qualification receipt: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close qualification receipt: %w", err)
	}
	success = true
	return nil
}

func signaturePayload(receipt Receipt) ([]byte, error) {
	receipt.SignatureB64URL = ""
	compact, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, qualificationSignatureDomain...), compact...), nil
}

func validateReceiptFields(receipt Receipt, options VerifyOptions) error {
	if receipt.Schema != ReceiptSchema || !validIdentifier(receipt.RunID) ||
		!validIdentifier(receipt.CandidateID) || stringsLowerHex(receipt.CandidateConfigSHA256) == "" ||
		stringsLowerHex(receipt.AdapterEndpointSetSHA256) == "" ||
		stringsLowerHex(receipt.QualificationToolSHA256) == "" ||
		stringsLowerHex(receipt.TransportTrustSHA256) == "" ||
		stringsLowerHex(receipt.CorpusSHA256) == "" ||
		stringsLowerHex(receipt.Codec.FixtureManifestSHA256) == "" ||
		stringsLowerHex(receipt.Codec.FFmpegSHA256) == "" || receipt.Codec.FFmpegVersion == "" ||
		!validIdentifier(receipt.SigningKeyID) || receipt.SignatureAlgorithm != "Ed25519" {
		return fmt.Errorf("qualification receipt identity fields are invalid")
	}
	switch receipt.ConsentClass {
	case "synthetic", "approved_nonprivate", "approved_private":
	default:
		return fmt.Errorf("qualification receipt consent class is invalid")
	}
	minimumTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	maximumTime := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	if receipt.StartedAtUnixMS < minimumTime || receipt.CompletedAtUnixMS < receipt.StartedAtUnixMS ||
		receipt.CompletedAtUnixMS-receipt.StartedAtUnixMS > int64((30*time.Minute)/time.Millisecond) ||
		receipt.CompletedAtUnixMS > maximumTime || receipt.ReadinessMS < 0 {
		return fmt.Errorf("qualification receipt timing is invalid")
	}
	if receipt.ProductionReady || !reflect.DeepEqual(receipt.UnresolvedProductionGates, requiredUnresolvedGates) ||
		!sort.StringsAreSorted(receipt.UnresolvedProductionGates) {
		return fmt.Errorf("qualification receipt overstates production readiness")
	}
	expectedStatus := "PROTOCOL_PASS"
	if receipt.DevelopmentOnly {
		expectedStatus = "TEST_HARNESS_PASS"
	}
	if receipt.QualificationStatus != expectedStatus ||
		(options.RequireProductionTransport && receipt.DevelopmentOnly) {
		return fmt.Errorf("qualification status or transport boundary is invalid")
	}
	metadata := ProbeMetadata{
		RunID: receipt.RunID, CandidateID: receipt.CandidateID,
		CandidateConfigSHA256:    receipt.CandidateConfigSHA256,
		AdapterEndpointSetSHA256: receipt.AdapterEndpointSetSHA256,
		QualificationToolSHA256:  receipt.QualificationToolSHA256,
		TransportTrustSHA256:     receipt.TransportTrustSHA256,
		CorpusSHA256:             receipt.CorpusSHA256, ConsentClass: receipt.ConsentClass,
		DevelopmentOnly: receipt.DevelopmentOnly, Thresholds: receipt.Thresholds,
	}
	loaded := LoadedCorpus{SHA256: receipt.CorpusSHA256, Corpus: Corpus{ConsentClass: receipt.ConsentClass}}
	if err := validateMetadata(metadata, loaded); err != nil {
		return err
	}
	if !validIdentifier(receipt.STT.CaseID) || receipt.STT.InputPackets < 1 ||
		receipt.STT.InputPackets > maximumPackets ||
		receipt.STT.InputDurationMS != receipt.STT.InputPackets*60 ||
		stringsLowerHex(receipt.STT.InputPacketStreamSHA256) == "" ||
		stringsLowerHex(receipt.STT.DecodedPCMSetSHA256) == "" ||
		!receipt.STT.TranscriptExactMatch || !receipt.STT.SingleFinalObserved ||
		receipt.STT.FinalAfterStopMS < 0 ||
		receipt.STT.FinalAfterStopMS > receipt.Thresholds.MaxSTTFinalMS ||
		!receipt.STT.AbortNoFinalObserved ||
		receipt.STT.AbortObservationMS < receipt.Thresholds.MaxCancelReturnMS {
		return fmt.Errorf("qualification STT evidence is invalid")
	}
	if len(receipt.TTS) < 2 || len(receipt.TTS) > maximumCases {
		return fmt.Errorf("qualification TTS evidence count is invalid")
	}
	caseIDs := map[string]bool{receipt.STT.CaseID: true}
	requestIDs := map[uint32]bool{}
	packetHashes := map[string]bool{}
	pcmHashes := map[string]bool{}
	previous := ""
	for _, result := range receipt.TTS {
		if !validIdentifier(result.CaseID) || caseIDs[result.CaseID] ||
			(previous != "" && result.CaseID <= previous) || result.RequestID == 0 ||
			requestIDs[result.RequestID] ||
			result.Frames < 1 || result.Frames > maximumPackets ||
			result.DecodedSamples != result.Frames*1440 ||
			stringsLowerHex(result.PacketStreamSHA256) == "" ||
			stringsLowerHex(result.DecodedPCMSetSHA256) == "" ||
			result.FirstFrameMS < 0 || result.FirstFrameMS > receipt.Thresholds.MaxTTSFirstFrameMS ||
			result.CompleteMS < result.FirstFrameMS ||
			result.CompleteMS > receipt.Thresholds.MaxTTSCompleteMS || !result.EveryFrameNonSilent {
			return fmt.Errorf("qualification TTS evidence is invalid")
		}
		caseIDs[result.CaseID], requestIDs[result.RequestID] = true, true
		packetHashes[result.PacketStreamSHA256], pcmHashes[result.DecodedPCMSetSHA256] = true, true
		previous = result.CaseID
	}
	if len(packetHashes) != len(receipt.TTS) || len(pcmHashes) != len(receipt.TTS) ||
		!validIdentifier(receipt.Cancel.CaseID) || caseIDs[receipt.Cancel.CaseID] ||
		receipt.Cancel.RequestID == 0 || requestIDs[receipt.Cancel.RequestID] ||
		receipt.Cancel.FramesBeforeCancel != 1 ||
		receipt.Cancel.CancelToReturnMS < 0 ||
		receipt.Cancel.CancelToReturnMS > receipt.Thresholds.MaxCancelReturnMS ||
		!receipt.Cancel.ReturnedContextCancel {
		return fmt.Errorf("qualification isolation or cancellation evidence is invalid")
	}
	if options.ExpectedSigningKeyID != "" && receipt.SigningKeyID != options.ExpectedSigningKeyID {
		return fmt.Errorf("qualification signing key ID differs from trust policy")
	}
	if options.ExpectedRunID != "" && receipt.RunID != options.ExpectedRunID {
		return fmt.Errorf("qualification run ID differs from expectation")
	}
	if options.ExpectedCandidateID != "" && receipt.CandidateID != options.ExpectedCandidateID {
		return fmt.Errorf("qualification candidate differs from expectation")
	}
	if options.ExpectedCandidateConfig != "" &&
		receipt.CandidateConfigSHA256 != options.ExpectedCandidateConfig {
		return fmt.Errorf("qualification candidate config differs from expectation")
	}
	if options.ExpectedEndpointSet != "" &&
		receipt.AdapterEndpointSetSHA256 != options.ExpectedEndpointSet {
		return fmt.Errorf("qualification endpoint set differs from expectation")
	}
	if options.ExpectedQualificationTool != "" &&
		receipt.QualificationToolSHA256 != options.ExpectedQualificationTool {
		return fmt.Errorf("qualification tool digest differs from expectation")
	}
	if options.ExpectedTransportTrust != "" &&
		receipt.TransportTrustSHA256 != options.ExpectedTransportTrust {
		return fmt.Errorf("qualification transport trust differs from expectation")
	}
	if options.ExpectedCorpusSHA256 != "" && receipt.CorpusSHA256 != options.ExpectedCorpusSHA256 {
		return fmt.Errorf("qualification corpus differs from expectation")
	}
	if options.ExpectedConsentClass != "" && receipt.ConsentClass != options.ExpectedConsentClass {
		return fmt.Errorf("qualification consent class differs from expectation")
	}
	if options.ExpectedFixtureManifest != "" &&
		receipt.Codec.FixtureManifestSHA256 != options.ExpectedFixtureManifest {
		return fmt.Errorf("qualification codec fixture manifest differs from expectation")
	}
	if options.ExpectedFFmpegSHA256 != "" && receipt.Codec.FFmpegSHA256 != options.ExpectedFFmpegSHA256 {
		return fmt.Errorf("qualification FFmpeg differs from expectation")
	}
	if options.RequireExpectedThresholds && receipt.Thresholds != options.ExpectedThresholds {
		return fmt.Errorf("qualification thresholds differ from expectation")
	}
	return nil
}

func loadPrivateKey(name string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return nil, fmt.Errorf("qualification private key must be a regular mode-0600 file")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read qualification private key")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("qualification private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("qualification private key must be Ed25519 PKCS8")
	}
	return key, nil
}

func loadPublicKey(name string) (ed25519.PublicKey, error) {
	data, err := readRegular(name, 4096)
	if err != nil {
		return nil, fmt.Errorf("trusted qualification public key is unavailable")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("trusted qualification public key PEM is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted qualification public key must be Ed25519")
	}
	return key, nil
}
