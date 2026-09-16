package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xiaozhi-agent-platform/gateway/internal/agentproxy"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/identityruntime"
	"xiaozhi-agent-platform/gateway/internal/ownershipruntime"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
	"xiaozhi-agent-platform/gateway/internal/usagebudget"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo}))
	settings, err := agentproxy.LoadSettings()
	if err != nil {
		logger.Error("configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings("agentproxy", settings.AllowInsecure)
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
		logger.Error("ownership resolver rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	defer ownership.Close()
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
	var usageLedger usagebudget.Ledger
	if settings.UsageBudgetEnabled {
		postgresLedger, ledgerErr := usagebudget.NewPostgresLedger(
			ownership.Database, settings.UsagePricing, settings.UsageDigestKey,
			ownership.OperationTimeout)
		if ledgerErr == nil {
			ledgerErr = postgresLedger.VerifySchema(context.Background())
		}
		if ledgerErr != nil {
			logger.Error("Agent usage budget rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		usageLedger = postgresLedger
	}
	var verifier *auth.Verifier
	if settings.AgentTokenKeyring != nil {
		verifier, err = auth.NewManagedKeyringVerifierForAudience(
			settings.AgentTokenKeyring, settings.AgentTokenMaxTTL,
			auth.AgentAudience)
	} else {
		verifier, err = auth.NewKeyringVerifierForAudience(
			settings.AgentTokenKeys, settings.AgentTokenMaxTTL,
			auth.AgentAudience)
	}
	if err != nil {
		logger.Error("Agent token verifier rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	identityRegistry, identityUpdater, err := identityruntime.Load(
		context.Background(), settings.Identity,
		provisioning.AccessSnapshotPurpose, time.Now)
	if err != nil {
		logger.Error("device identity rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	providerTransport, err := traceRuntime.WrapTransport("agent.provider",
		&http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		}})
	if err != nil {
		logger.Error("Agent provider telemetry rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	outbound := &http.Client{
		Timeout:   settings.RequestTimeout,
		Transport: providerTransport,
	}
	proxy, err := agentproxy.New(agentproxy.Config{
		Verifier: verifier, IdentityRegistry: identityRegistry,
		Ownership:            ownership.Resolver,
		AllowInsecure:        settings.AllowInsecure,
		ProviderURL:          settings.ProviderURL,
		ProviderAPIKey:       settings.ProviderAPIKey,
		ProviderModel:        settings.ProviderModel,
		ProviderOrganization: settings.ProviderOrganization,
		ProviderProject:      settings.ProviderProject,
		PublicModel:          settings.PublicModel, HTTPClient: outbound,
		Logger: logger, MaxOutputTokens: settings.MaxOutputTokens,
		MaxRequestBytes:    settings.MaxRequestBytes,
		MaxResponseBytes:   settings.MaxResponseBytes,
		RequestTimeout:     settings.RequestTimeout,
		MaxConcurrent:      settings.MaxConcurrent,
		MaxRequestsMinute:  settings.MaxRequestsMinute,
		RuntimeCoordinator: coordinator,
		UsageLedger:        usageLedger,
		InputTokenOverhead: settings.UsagePricing.InputTokenOverhead,
	})
	if err != nil {
		logger.Error("Agent proxy rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	server := &http.Server{
		Addr: settings.Address, Handler: traceRuntime.WrapHandler(proxy.Handler()),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 75 * time.Second,
		MaxHeaderBytes: 16 * 1024,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
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
				if canceled := proxy.ReconcileIdentity(); canceled > 0 {
					logger.Warn("Agent requests canceled by identity",
						"count", canceled, "revision", event.Status.Revision)
				}
			})
	}
	errChannel := make(chan error, 1)
	go func() {
		logger.Info("Agent proxy starting", "address", settings.Address,
			"tls", settings.TLSCertFile != "")
		if settings.TLSCertFile != "" {
			errChannel <- server.ListenAndServeTLS(
				settings.TLSCertFile, settings.TLSKeyFile)
			return
		}
		errChannel <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(
			context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("Agent proxy shutdown failed",
				"error_class", "shutdown_failed")
			os.Exit(1)
		}
	case err := <-errChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Agent proxy stopped", "error_class", "server_failed")
			os.Exit(1)
		}
	}
	traceShutdownContext, traceCancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	if err := traceRuntime.Shutdown(traceShutdownContext); err != nil {
		logger.Error("telemetry shutdown failed", "error_class", "shutdown_failed")
	}
	traceCancel()
	logger.Info("Agent proxy stopped")
}
