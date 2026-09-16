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

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/firmwareorigin"
	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/identityruntime"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo}))
	settings, err := firmwareorigin.LoadSettings()
	if err != nil {
		logger.Error("configuration rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings("firmwareorigin", settings.AllowInsecure)
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
	if err := generation.VerifyOriginBundle(settings.Generation.BundleRoot,
		settings.CatalogFile); err != nil {
		logger.Error("firmware generation catalog binding rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	identity, err := generation.LoadBundleGeneration(settings.Generation.BundleRoot)
	if err != nil {
		logger.Error("firmware generation receipt rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	generationTransport, err := traceRuntime.WrapTransport(
		"generation.coordinator", http.DefaultTransport)
	if err != nil {
		logger.Error("generation telemetry rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	generationClient, err := generation.NewClient(
		settings.Generation.CoordinatorURL, settings.Generation.Replica,
		generationTransport, settings.AllowInsecure)
	if err != nil {
		logger.Error("generation coordinator client rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	replicaGuard, err := generation.NewReplicaGuard(generationClient, identity)
	if err != nil {
		logger.Error("generation replica guard rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	catalog, err := firmwareorigin.LoadCatalog(settings.CatalogFile)
	if err != nil {
		logger.Error("firmware catalog rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	var verifier *auth.Verifier
	if settings.OTATokenKeyring != nil {
		verifier, err = auth.NewManagedKeyringVerifierForAudience(
			settings.OTATokenKeyring, settings.OTATokenMaxTTL,
			auth.OTAAudience)
	} else {
		verifier, err = auth.NewKeyringVerifierForAudience(
			settings.OTATokenKeys, settings.OTATokenMaxTTL,
			auth.OTAAudience)
	}
	if err != nil {
		logger.Error("OTA token verifier rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	identityRegistry, identityUpdater, err := identityruntime.Load(
		context.Background(), settings.Identity,
		provisioning.AccessSnapshotPurpose, time.Now)
	if err != nil {
		logger.Error("device identity rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	origin, err := firmwareorigin.New(firmwareorigin.Config{
		Catalog: catalog, Verifier: verifier, Logger: logger,
		MaxConcurrent:    settings.MaxConcurrent,
		PublicAuthority:  settings.PublicAuthority,
		GenerationGate:   replicaGuard,
		IdentityRegistry: identityRegistry,
	})
	if err != nil {
		logger.Error("firmware origin rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	server := &http.Server{
		Addr: settings.Address, Handler: traceRuntime.WrapHandler(origin.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      settings.WriteTimeout,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go replicaGuard.Run(ctx)
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
				if canceled := origin.ReconcileIdentity(); canceled > 0 {
					logger.Warn("firmware downloads canceled by identity",
						"count", canceled, "revision", event.Status.Revision)
				}
			})
	}
	errChannel := make(chan error, 1)
	go func() {
		logger.Info("firmware origin starting", "address", settings.Address,
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
			context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("firmware origin shutdown failed",
				"error_class", "shutdown_failed")
			os.Exit(1)
		}
	case err := <-errChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("firmware origin stopped",
				"error_class", "server_failed")
			os.Exit(1)
		}
	}
	traceShutdownContext, traceCancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	if err := traceRuntime.Shutdown(traceShutdownContext); err != nil {
		logger.Error("telemetry shutdown failed", "error_class", "shutdown_failed")
	}
	traceCancel()
	logger.Info("firmware origin stopped")
}
