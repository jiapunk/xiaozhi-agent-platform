package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/config"
	devicegateway "xiaozhi-agent-platform/gateway/internal/gateway"
	"xiaozhi-agent-platform/gateway/internal/identityruntime"
	"xiaozhi-agent-platform/gateway/internal/ownershipruntime"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
	"xiaozhi-agent-platform/gateway/internal/speechbudget"
	"xiaozhi-agent-platform/gateway/internal/speechidentity"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
	"xiaozhi-agent-platform/gateway/internal/tts"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings, err := config.Load()
	if err != nil {
		logger.Error("configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	if settings.EnableSessionIssuance {
		logger.Error("standalone session issuance is disabled; use the ownership-aware control plane",
			"error_class", "ownership_resolver_required")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings("gateway", settings.AllowInsecure)
	if err != nil {
		logger.Error("telemetry configuration rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceRuntime, err := telemetry.New(context.Background(), traceSettings)
	if err != nil {
		logger.Error("telemetry identity rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	ownership, err := ownershipruntime.OpenFromEnvironment(settings.AllowInsecure)
	if err != nil {
		logger.Error("ownership resolver rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	defer ownership.Close()
	var speechLedger speechbudget.Ledger
	if settings.AllowInsecure {
		ephemeralKey := make([]byte, 32)
		if _, err = rand.Read(ephemeralKey); err == nil {
			speechLedger, err = speechbudget.NewMemoryLedger(
				settings.SpeechPricing, ephemeralKey)
		}
	} else {
		var digestKey []byte
		digestKey, err = speechbudget.LoadDigestKey(
			settings.SpeechUsageDigestKeyFile)
		if err == nil {
			speechLedger, err = speechbudget.NewPostgresLedger(
				ownership.Database, settings.SpeechPricing, digestKey,
				ownership.OperationTimeout)
		}
		if err == nil {
			err = speechLedger.VerifySchema(context.Background())
		}
	}
	if err != nil {
		logger.Error("speech usage budget rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	coordinator, err := runtimecoordination.NewPostgresCoordinator(
		ownership.Database, os.Getenv("RUNTIME_COORDINATION_WORKER_ID"),
		ownership.OperationTimeout)
	if err == nil {
		err = coordinator.VerifySchema(context.Background())
	}
	if err != nil {
		logger.Error("runtime coordinator rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	var verifier *auth.Verifier
	if settings.VoiceTokenKeyring != nil {
		verifier, err = auth.NewManagedKeyringVerifier(
			settings.VoiceTokenKeyring, settings.DeviceTokenMaxTTL)
	} else {
		verifier, err = auth.NewKeyringVerifier(
			settings.DeviceTokenKeys, settings.DeviceTokenMaxTTL)
	}
	if err != nil {
		logger.Error("device token verifier rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	var sessionProof *provisioning.ProofVerifier
	var sessionIssuer *auth.Issuer
	var publicDeviceWSS string
	identityRegistry, identityUpdater, err := identityruntime.Load(
		context.Background(), settings.Identity,
		provisioning.AccessSnapshotPurpose, time.Now)
	if err != nil {
		logger.Error("device registry rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	if settings.EnableSessionIssuance {
		sessionProof, err = provisioning.NewProofVerifier(identityRegistry,
			settings.SessionProofMaxSkew, settings.SessionMinInterval)
		if err != nil {
			logger.Error("device proof verifier rejected", "error_class", "invalid_configuration")
			os.Exit(2)
		}
		publicDeviceWSS = settings.PublicDeviceWSS
		if settings.VoiceTokenKeyring != nil {
			sessionIssuer, err = auth.NewManagedIssuerForAudience(
				settings.VoiceTokenKeyring, settings.SessionTokenTTL,
				auth.VoiceAudience)
		} else {
			sessionIssuer, err = auth.NewIssuer(
				settings.DeviceTokenKeys[0], settings.SessionTokenTTL)
		}
		if err != nil {
			logger.Error("device token issuer rejected", "error_class", "invalid_configuration")
			os.Exit(2)
		}
	}
	sttHTTPClient, ttsHTTPClient, err := loadSpeechTransports(settings)
	if err != nil {
		logger.Error("speech workload identity rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	if sttHTTPClient != nil {
		defer sttHTTPClient.CloseIdleConnections()
	}
	if ttsHTTPClient != nil {
		defer ttsHTTPClient.CloseIdleConnections()
	}
	if sttHTTPClient != nil {
		sttHTTPClient.Transport, err = traceRuntime.WrapTransport(
			"speech.stt", sttHTTPClient.Transport)
	}
	if err == nil && ttsHTTPClient != nil {
		ttsHTTPClient.Transport, err = traceRuntime.WrapTransport(
			"speech.tts", ttsHTTPClient.Transport)
	}
	if err != nil {
		logger.Error("speech telemetry rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	sttBackend, err := devicegateway.NewWebSocketSTT(devicegateway.WebSocketSTTConfig{
		Endpoint: settings.STTURL, HealthURL: settings.STTHealthURL,
		BearerToken: settings.STTToken, AllowInsecure: settings.AllowInsecure,
		HTTPClient: sttHTTPClient,
	})
	if err != nil {
		logger.Error("STT configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	ttsBackend, err := tts.NewFramedHTTP(tts.FramedHTTPConfig{
		Endpoint: settings.TTSURL, HealthURL: settings.TTSHealthURL,
		BearerToken: settings.TTSToken, AllowInsecure: settings.AllowInsecure,
		SampleRate: settings.OutputSampleRate, FrameDuration: settings.OutputFrameMillis,
		MaxOutputAudioMS: settings.SpeechPricing.TTSMaxOutputAudioMS,
		Client:           ttsHTTPClient,
	})
	if err != nil {
		logger.Error("TTS configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	gateway, err := devicegateway.New(devicegateway.Config{
		Verifier: verifier, Synthesizer: ttsBackend, VoiceBackend: sttBackend,
		Logger: logger, MaxConnections: settings.MaxConnections,
		MaxMessagesMinute:  settings.MaxMessagesPerMinute,
		MaxAudioMinute:     settings.MaxAudioPacketsMinute,
		IdentityRegistry:   identityRegistry,
		Ownership:          ownership.Resolver,
		OutputSampleRate:   settings.OutputSampleRate,
		OutputFrameMillis:  settings.OutputFrameMillis,
		SessionProof:       sessionProof,
		SessionIssuer:      sessionIssuer,
		PublicDeviceWSS:    publicDeviceWSS,
		RuntimeCoordinator: coordinator,
		SpeechUsageLedger:  speechLedger,
		SpeechPricing:      settings.SpeechPricing,
	})
	if err != nil {
		logger.Error("gateway configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}

	server := &http.Server{
		Addr: settings.Address, Handler: traceRuntime.WrapHandler(gateway.Handler()),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 75 * time.Second,
		MaxHeaderBytes: 16 * 1024,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if identityUpdater != nil {
		go identityUpdater.Run(ctx, settings.Identity.ReloadInterval,
			func(event provisioning.ReloadEvent) {
				if event.Err != nil {
					logger.Warn("device identity reload rejected",
						"revision", event.Status.Revision,
						"ready", event.Status.Ready,
						"error_class", "identity_reload_rejected")
				} else if event.Changed {
					logger.Info("device identity snapshot activated",
						"revision", event.Status.Revision,
						"valid_until", event.Status.ValidUntil)
				}
				revoked := gateway.ReconcileIdentity()
				if revoked > 0 {
					logger.Warn("device connections revoked", "count", revoked,
						"revision", event.Status.Revision)
				}
			})
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if revoked := gateway.ReconcileOwnership(); revoked > 0 {
					logger.Warn("voice sessions revoked by ownership",
						"count", revoked)
				}
			}
		}
	}()
	errChannel := make(chan error, 1)
	go func() {
		logger.Info("gateway starting", "address", settings.Address,
			"tls", settings.TLSCertFile != "")
		if settings.TLSCertFile != "" {
			errChannel <- server.ListenAndServeTLS(settings.TLSCertFile, settings.TLSKeyFile)
			return
		}
		errChannel <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := gateway.Shutdown(shutdownContext); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			logger.Error("WebSocket shutdown failed", "error_class", "shutdown_failed")
		}
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("gateway shutdown failed", "error_class", "shutdown_failed")
			os.Exit(1)
		}
	case err := <-errChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("gateway stopped", "error_class", "server_failed")
			os.Exit(1)
		}
	}
	traceShutdownContext, traceCancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	if err := traceRuntime.Shutdown(traceShutdownContext); err != nil {
		logger.Error("telemetry shutdown failed", "error_class", "shutdown_failed")
	}
	traceCancel()
	logger.Info("gateway stopped")
}

func loadSpeechTransports(settings config.Settings) (*http.Client, *http.Client, error) {
	if !settings.SpeechMTLSConfigured() {
		return nil, nil, nil
	}
	sttClient, sttBinding, err := speechidentity.LoadMTLSClient(speechidentity.Files{
		CACertificateFile:     settings.STTTLSCAFile,
		ClientCertificateFile: settings.STTTLSClientCertFile,
		ClientPrivateKeyFile:  settings.STTTLSClientKeyFile,
	}, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	ttsClient, ttsBinding, err := speechidentity.LoadMTLSClient(speechidentity.Files{
		CACertificateFile:     settings.TTSTLSCAFile,
		ClientCertificateFile: settings.TTSTLSClientCertFile,
		ClientPrivateKeyFile:  settings.TTSTLSClientKeyFile,
	}, 5*time.Second)
	if err != nil {
		sttClient.CloseIdleConnections()
		return nil, nil, err
	}
	if err := speechidentity.ValidateIsolation(sttBinding, ttsBinding); err != nil {
		sttClient.CloseIdleConnections()
		ttsClient.CloseIdleConnections()
		return nil, nil, err
	}
	return sttClient, ttsClient, nil
}
