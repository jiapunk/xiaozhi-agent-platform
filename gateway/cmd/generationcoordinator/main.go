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

	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo}))
	settings, err := generation.LoadCoordinatorSettings()
	if err != nil {
		logger.Error("configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings(
		"generationcoordinator", settings.AllowInsecure)
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
	registry, err := generation.LoadReplicaRegistry(settings.ReplicaRegistryFile)
	if err != nil {
		logger.Error("replica registry rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	store, err := generation.OpenStore(settings.StateDirectory, settings.StateKey)
	if err != nil {
		logger.Error("generation state rejected", "error_class", "invalid_state")
		os.Exit(2)
	}
	defer store.Close()
	coordinator, err := generation.NewServer(generation.ServerConfig{
		Store: store, Publisher: settings.Publisher, Replicas: registry,
		PrepareTimeout: settings.PrepareTimeout,
		CommitTimeout:  settings.CommitTimeout,
		MaxClockSkew:   settings.MaxClockSkew, Logger: logger,
	})
	if err != nil {
		logger.Error("generation coordinator rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	server := &http.Server{
		Addr:              settings.Address,
		Handler:           traceRuntime.WrapHandler(coordinator.Handler()),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 75 * time.Second,
		MaxHeaderBytes: 16 * 1024,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go coordinator.Run(ctx.Done())
	errChannel := make(chan error, 1)
	go func() {
		logger.Info("generation coordinator starting", "address", settings.Address,
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
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("generation coordinator shutdown failed",
				"error_class", "shutdown_failed")
			os.Exit(1)
		}
	case err := <-errChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("generation coordinator stopped", "error_class", "server_failed")
			os.Exit(1)
		}
	}
	traceShutdownContext, traceCancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	if err := traceRuntime.Shutdown(traceShutdownContext); err != nil {
		logger.Error("telemetry shutdown failed", "error_class", "shutdown_failed")
	}
	traceCancel()
	logger.Info("generation coordinator stopped")
}
