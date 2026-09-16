package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	voicegateway "xiaozhi-agent-platform/gateway/internal/gateway"
	"xiaozhi-agent-platform/gateway/internal/speechidentity"
	"xiaozhi-agent-platform/gateway/internal/speechqualification"
	"xiaozhi-agent-platform/gateway/internal/tts"
)

func main() {
	runID := flag.String("run-id", "", "unique immutable qualification run ID")
	candidateID := flag.String("candidate-id", "", "candidate provider/model/voice/region ID")
	candidateConfig := flag.String("candidate-config", "", "immutable non-secret candidate config")
	corpusName := flag.String("corpus", "", "approved canonical qualification corpus")
	codecFixtures := flag.String("codec-fixtures", "", "M27 codec fixture manifest")
	ffmpeg := flag.String("ffmpeg", "", "reviewed hash-pinned FFmpeg executable")
	toolDigest := flag.String("qualification-tool-sha256", "", "externally approved runner source/image digest")
	sttURL := flag.String("stt-url", "", "candidate private STT WebSocket URL")
	sttHealthURL := flag.String("stt-health-url", "", "candidate private STT readiness URL")
	ttsURL := flag.String("tts-url", "", "candidate private TTS HTTP URL")
	ttsHealthURL := flag.String("tts-health-url", "", "candidate private TTS readiness URL")
	bearerTokenFile := flag.String("bearer-token-file", "", "development-only shared adapter bearer-token file")
	caBundle := flag.String("ca-bundle", "", "development-only optional private CA PEM bundle")
	sttBearerTokenFile := flag.String("stt-bearer-token-file", "", "mode-0600 STT bearer-token file")
	ttsBearerTokenFile := flag.String("tts-bearer-token-file", "", "mode-0600 TTS bearer-token file")
	sttCA := flag.String("stt-ca-bundle", "", "private STT server CA PEM bundle")
	sttClientCertificate := flag.String("stt-client-certificate", "", "STT client certificate PEM")
	sttClientKey := flag.String("stt-client-key", "", "mode-0600 STT client private key")
	ttsCA := flag.String("tts-ca-bundle", "", "private TTS server CA PEM bundle")
	ttsClientCertificate := flag.String("tts-client-certificate", "", "TTS client certificate PEM")
	ttsClientKey := flag.String("tts-client-key", "", "mode-0600 TTS client private key")
	privateKey := flag.String("signing-private-key", "", "mode-0600 Ed25519 PKCS8 qualification key")
	signingKeyID := flag.String("signing-key-id", "", "qualification signing key ID")
	output := flag.String("output", "", "new signed receipt path; must not exist")
	allowInsecure := flag.Bool("allow-insecure-development", false, "allow local HTTP/WS and mark receipt development-only")
	timeout := flag.Duration("timeout", 2*time.Minute, "whole-probe timeout")
	maxSTT := flag.Int64("max-stt-final-ms", 0, "frozen stop-to-final threshold")
	maxFirst := flag.Int64("max-tts-first-frame-ms", 0, "frozen TTS first-frame threshold")
	maxComplete := flag.Int64("max-tts-complete-ms", 0, "frozen TTS completion threshold")
	maxCancel := flag.Int64("max-cancel-return-ms", 0, "frozen cancellation-return threshold")
	flag.Parse()

	required := []*string{
		runID, candidateID, candidateConfig, corpusName, codecFixtures, ffmpeg, toolDigest,
		sttURL, sttHealthURL, ttsURL, ttsHealthURL,
		privateKey, signingKeyID, output,
	}
	for _, value := range required {
		if strings.TrimSpace(*value) == "" {
			fatal("all identity, endpoint, corpus, codec, key, and output flags are required")
		}
	}
	if *timeout < time.Second || *timeout > 30*time.Minute {
		fatal("timeout is outside policy")
	}
	sttToken, ttsToken, sttClient, ttsClient, transportTrust, err :=
		loadSpeechTransports(speechTransportFlags{
			legacyBearerTokenFile: *bearerTokenFile, legacyCABundle: *caBundle,
			sttBearerTokenFile: *sttBearerTokenFile, ttsBearerTokenFile: *ttsBearerTokenFile,
			sttCA: *sttCA, sttClientCertificate: *sttClientCertificate,
			sttClientKey: *sttClientKey, ttsCA: *ttsCA,
			ttsClientCertificate: *ttsClientCertificate, ttsClientKey: *ttsClientKey,
		}, *allowInsecure)
	if err != nil {
		fatal(err.Error())
	}
	defer sttClient.CloseIdleConnections()
	if ttsClient != sttClient {
		defer ttsClient.CloseIdleConnections()
	}
	loaded, err := speechqualification.LoadCorpus(*corpusName)
	if err != nil {
		fatal(err.Error())
	}
	configHash, err := speechqualification.DigestRegularFile(*candidateConfig, 1<<20)
	if err != nil {
		fatal("candidate config: " + err.Error())
	}
	decoder, err := speechqualification.NewReferenceDecoder(*ffmpeg, *codecFixtures)
	if err != nil {
		fatal(err.Error())
	}
	voice, err := voicegateway.NewWebSocketSTT(voicegateway.WebSocketSTTConfig{
		Endpoint: *sttURL, HealthURL: *sttHealthURL, BearerToken: sttToken,
		HTTPClient: sttClient, AllowInsecure: *allowInsecure,
		ConnectTimeout: 10 * time.Second, WriteTimeout: 5 * time.Second,
	})
	if err != nil {
		fatal(err.Error())
	}
	synthesizer, err := tts.NewFramedHTTP(tts.FramedHTTPConfig{
		Endpoint: *ttsURL, HealthURL: *ttsHealthURL, BearerToken: ttsToken,
		Client: ttsClient, AllowInsecure: *allowInsecure, SampleRate: 24000, FrameDuration: 60,
	})
	if err != nil {
		fatal(err.Error())
	}
	probeContext, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := (speechqualification.Runner{
		Voice: voice, TTS: synthesizer, Decoder: decoder,
	}).Run(probeContext, loaded, speechqualification.ProbeMetadata{
		RunID: *runID, CandidateID: *candidateID,
		CandidateConfigSHA256: configHash, CorpusSHA256: loaded.SHA256,
		AdapterEndpointSetSHA256: speechqualification.EndpointSetDigest(
			*sttURL, *sttHealthURL, *ttsURL, *ttsHealthURL),
		QualificationToolSHA256: *toolDigest, TransportTrustSHA256: transportTrust,
		ConsentClass: loaded.Corpus.ConsentClass, DevelopmentOnly: *allowInsecure,
		Thresholds: speechqualification.Thresholds{
			MaxSTTFinalMS: *maxSTT, MaxTTSFirstFrameMS: *maxFirst,
			MaxTTSCompleteMS: *maxComplete, MaxCancelReturnMS: *maxCancel,
		},
	})
	if err != nil {
		fatal(err.Error())
	}
	signed, err := speechqualification.SignReceipt(receipt, *privateKey, *signingKeyID)
	if err != nil {
		fatal(err.Error())
	}
	if err := speechqualification.WriteNewReceipt(*output, signed); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("speech adapter qualification %s: candidate=%s run=%s receipt=%s\n",
		receipt.QualificationStatus, receipt.CandidateID, receipt.RunID, *output)
}

type speechTransportFlags struct {
	legacyBearerTokenFile string
	legacyCABundle        string
	sttBearerTokenFile    string
	ttsBearerTokenFile    string
	sttCA                 string
	sttClientCertificate  string
	sttClientKey          string
	ttsCA                 string
	ttsClientCertificate  string
	ttsClientKey          string
}

func loadSpeechTransports(flags speechTransportFlags, allowInsecure bool) (
	string, string, *http.Client, *http.Client, string, error) {
	isolated := []string{
		flags.sttBearerTokenFile, flags.ttsBearerTokenFile,
		flags.sttCA, flags.sttClientCertificate, flags.sttClientKey,
		flags.ttsCA, flags.ttsClientCertificate, flags.ttsClientKey,
	}
	configured := 0
	for _, value := range isolated {
		if strings.TrimSpace(value) != "" {
			configured++
		}
	}
	if configured == 0 && allowInsecure {
		if strings.TrimSpace(flags.legacyBearerTokenFile) == "" {
			return "", "", nil, nil, "", fmt.Errorf("development bearer-token-file is required")
		}
		token, err := loadSecret(flags.legacyBearerTokenFile)
		if err != nil {
			return "", "", nil, nil, "", err
		}
		client, trust, err := buildHTTPClient(flags.legacyCABundle)
		return token, token, client, client, trust, err
	}
	if configured != len(isolated) {
		return "", "", nil, nil, "", fmt.Errorf("all isolated STT and TTS token and mTLS flags are required")
	}
	if strings.TrimSpace(flags.legacyBearerTokenFile) != "" || strings.TrimSpace(flags.legacyCABundle) != "" {
		return "", "", nil, nil, "", fmt.Errorf("legacy shared speech flags cannot be combined with isolated mTLS")
	}
	sttToken, err := loadSecret(flags.sttBearerTokenFile)
	if err != nil {
		return "", "", nil, nil, "", err
	}
	ttsToken, err := loadSecret(flags.ttsBearerTokenFile)
	if err != nil {
		return "", "", nil, nil, "", err
	}
	if sttToken == ttsToken {
		return "", "", nil, nil, "", fmt.Errorf("STT and TTS bearer tokens must be isolated")
	}
	sttClient, sttBinding, err := speechidentity.LoadMTLSClient(speechidentity.Files{
		CACertificateFile: flags.sttCA, ClientCertificateFile: flags.sttClientCertificate,
		ClientPrivateKeyFile: flags.sttClientKey,
	}, 5*time.Second)
	if err != nil {
		return "", "", nil, nil, "", err
	}
	ttsClient, ttsBinding, err := speechidentity.LoadMTLSClient(speechidentity.Files{
		CACertificateFile: flags.ttsCA, ClientCertificateFile: flags.ttsClientCertificate,
		ClientPrivateKeyFile: flags.ttsClientKey,
	}, 5*time.Second)
	if err != nil {
		sttClient.CloseIdleConnections()
		return "", "", nil, nil, "", err
	}
	trust := speechidentity.BindingSetDigest(sttBinding, ttsBinding)
	if trust == "" {
		sttClient.CloseIdleConnections()
		ttsClient.CloseIdleConnections()
		return "", "", nil, nil, "", fmt.Errorf("STT and TTS mTLS identities are not isolated")
	}
	return sttToken, ttsToken, sttClient, ttsClient, trust, nil
}

func loadSecret(name string) (string, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return "", fmt.Errorf("adapter bearer token must be a regular mode-0600 file")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("cannot read adapter bearer token")
	}
	token := strings.TrimSpace(string(data))
	if token == "" || len(token) > 2048 || strings.ContainsAny(token, " \t\r\n\x00") {
		return "", fmt.Errorf("adapter bearer token has invalid format")
	}
	return token, nil
}

func buildHTTPClient(caBundleName string) (*http.Client, string, error) {
	configuration := &tls.Config{MinVersion: tls.VersionTLS12}
	trustDigest := speechqualification.TransportTrustDigest("")
	if caBundleName != "" {
		info, err := os.Lstat(caBundleName)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() < 1 || info.Size() > 1<<20 {
			return nil, "", fmt.Errorf("private CA bundle must be a bounded regular file")
		}
		data, err := os.ReadFile(caBundleName)
		if err != nil {
			return nil, "", fmt.Errorf("cannot read private CA bundle")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, "", fmt.Errorf("private CA bundle contains no certificates")
		}
		configuration.RootCAs = roots
		caHash := sha256.Sum256(data)
		trustDigest = speechqualification.TransportTrustDigest(hex.EncodeToString(caHash[:]))
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: configuration, DisableCompression: true,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}}, trustDigest, nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "ERROR:", message)
	os.Exit(1)
}
