package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/speechqualification"
)

func main() {
	receiptName := flag.String("receipt", "", "signed qualification receipt")
	publicKey := flag.String("public-key", "", "trusted Ed25519 public key")
	keyID := flag.String("signing-key-id", "", "expected qualification key ID")
	runID := flag.String("run-id", "", "expected immutable run ID")
	candidateID := flag.String("candidate-id", "", "expected candidate ID")
	candidateConfig := flag.String("candidate-config-sha256", "", "expected candidate config digest")
	endpointSet := flag.String("endpoint-set-sha256", "", "expected tested endpoint-set digest")
	toolDigest := flag.String("qualification-tool-sha256", "", "expected approved runner source/image digest")
	transportTrust := flag.String("transport-trust-sha256", "", "expected CA/system-trust policy digest")
	corpusDigest := flag.String("corpus-sha256", "", "expected approved corpus digest")
	consentClass := flag.String("consent-class", "", "expected approved consent class")
	fixtureManifest := flag.String("codec-fixture-manifest-sha256", "", "expected M27 fixture-manifest digest")
	ffmpegDigest := flag.String("ffmpeg-sha256", "", "expected reviewed FFmpeg digest")
	maxSTT := flag.Int64("max-stt-final-ms", 0, "expected frozen stop-to-final threshold")
	maxFirst := flag.Int64("max-tts-first-frame-ms", 0, "expected frozen first-frame threshold")
	maxComplete := flag.Int64("max-tts-complete-ms", 0, "expected frozen completion threshold")
	maxCancel := flag.Int64("max-cancel-return-ms", 0, "expected frozen cancellation threshold")
	requireProduction := flag.Bool("require-production-transport", false, "reject HTTP/WS development evidence")
	flag.Parse()
	if *receiptName == "" || *publicKey == "" || *keyID == "" ||
		*runID == "" || *candidateID == "" || *candidateConfig == "" || *endpointSet == "" ||
		*toolDigest == "" || *transportTrust == "" || *corpusDigest == "" ||
		*consentClass == "" || *fixtureManifest == "" || *ffmpegDigest == "" ||
		*maxSTT <= 0 || *maxFirst <= 0 || *maxComplete <= 0 || *maxCancel <= 0 {
		fmt.Fprintln(os.Stderr, "ERROR: every trust-policy flag is required")
		os.Exit(1)
	}
	receipt, err := speechqualification.VerifyReceiptFile(*receiptName, speechqualification.VerifyOptions{
		TrustedPublicKey: *publicKey, ExpectedSigningKeyID: *keyID,
		ExpectedRunID: *runID, ExpectedCandidateID: *candidateID,
		ExpectedCandidateConfig: *candidateConfig, ExpectedEndpointSet: *endpointSet,
		ExpectedQualificationTool: *toolDigest, ExpectedTransportTrust: *transportTrust,
		ExpectedCorpusSHA256: *corpusDigest, ExpectedConsentClass: *consentClass,
		ExpectedFixtureManifest: *fixtureManifest, ExpectedFFmpegSHA256: *ffmpegDigest,
		ExpectedThresholds: speechqualification.Thresholds{
			MaxSTTFinalMS: *maxSTT, MaxTTSFirstFrameMS: *maxFirst,
			MaxTTSCompleteMS: *maxComplete, MaxCancelReturnMS: *maxCancel,
		},
		RequireExpectedThresholds:  true,
		RequireProductionTransport: *requireProduction,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("speech qualification verified: status=%s candidate=%s run=%s production_ready=%t\n",
		receipt.QualificationStatus, receipt.CandidateID, receipt.RunID, receipt.ProductionReady)
}
