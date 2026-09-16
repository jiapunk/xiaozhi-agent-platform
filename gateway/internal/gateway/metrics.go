package gateway

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Metrics struct {
	connections                 atomic.Int64
	authFailures                atomic.Int64
	protocolViolations          atomic.Int64
	ttsRequests                 atomic.Int64
	ttsAborts                   atomic.Int64
	ttsErrors                   atomic.Int64
	sessionIssued               atomic.Int64
	sessionProofErrors          atomic.Int64
	sessionReplays              atomic.Int64
	sessionRateLimited          atomic.Int64
	voiceTokenReplays           atomic.Int64
	voiceTokenExpirations       atomic.Int64
	identityRevocations         atomic.Int64
	ownershipRevocations        atomic.Int64
	runtimeCoordinationFailures atomic.Int64
	speechBudgetRejected        atomic.Int64
	speechSettledReservations   atomic.Int64
	speechUncertainReservations atomic.Int64
	speechCommittedMicrousd     atomic.Int64
	speechUncertainMicrousd     atomic.Int64
	speechSTTAudioMS            atomic.Int64
	speechTTSCharacters         atomic.Int64
	speechTTSOutputAudioMS      atomic.Int64
	speechUsageFailures         atomic.Int64
}

func (metrics *Metrics) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(writer,
		"xiaozhi_gateway_connections %d\n"+
			"xiaozhi_gateway_auth_failures_total %d\n"+
			"xiaozhi_gateway_protocol_violations_total %d\n"+
			"xiaozhi_gateway_tts_requests_total %d\n"+
			"xiaozhi_gateway_tts_aborts_total %d\n"+
			"xiaozhi_gateway_tts_errors_total %d\n"+
			"xiaozhi_gateway_session_issued_total %d\n"+
			"xiaozhi_gateway_session_proof_errors_total %d\n"+
			"xiaozhi_gateway_session_replays_total %d\n"+
			"xiaozhi_gateway_session_rate_limited_total %d\n"+
			"xiaozhi_gateway_voice_token_replays_total %d\n"+
			"xiaozhi_gateway_voice_token_expirations_total %d\n"+
			"xiaozhi_gateway_identity_revocations_total %d\n"+
			"xiaozhi_gateway_ownership_revocations_total %d\n"+
			"xiaozhi_gateway_runtime_coordination_failures_total %d\n"+
			"xiaozhi_gateway_speech_budget_rejected_total %d\n"+
			"xiaozhi_gateway_speech_settled_reservations_total %d\n"+
			"xiaozhi_gateway_speech_uncertain_reservations_total %d\n"+
			"xiaozhi_gateway_speech_committed_microusd_total %d\n"+
			"xiaozhi_gateway_speech_uncertain_microusd_total %d\n"+
			"xiaozhi_gateway_speech_stt_audio_ms_total %d\n"+
			"xiaozhi_gateway_speech_tts_characters_total %d\n"+
			"xiaozhi_gateway_speech_tts_output_audio_ms_total %d\n"+
			"xiaozhi_gateway_speech_usage_failures_total %d\n",
		metrics.connections.Load(), metrics.authFailures.Load(),
		metrics.protocolViolations.Load(), metrics.ttsRequests.Load(),
		metrics.ttsAborts.Load(), metrics.ttsErrors.Load(),
		metrics.sessionIssued.Load(), metrics.sessionProofErrors.Load(),
		metrics.sessionReplays.Load(), metrics.sessionRateLimited.Load(),
		metrics.voiceTokenReplays.Load(), metrics.voiceTokenExpirations.Load(),
		metrics.identityRevocations.Load(),
		metrics.ownershipRevocations.Load(),
		metrics.runtimeCoordinationFailures.Load(),
		metrics.speechBudgetRejected.Load(),
		metrics.speechSettledReservations.Load(),
		metrics.speechUncertainReservations.Load(),
		metrics.speechCommittedMicrousd.Load(),
		metrics.speechUncertainMicrousd.Load(),
		metrics.speechSTTAudioMS.Load(), metrics.speechTTSCharacters.Load(),
		metrics.speechTTSOutputAudioMS.Load(), metrics.speechUsageFailures.Load())
}
