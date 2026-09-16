package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"xiaozhi-agent-platform/gateway/internal/factorytime"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo}))
	settings, err := factorytime.LoadSettings()
	if err != nil {
		logger.Error("configuration rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings("factorytimeauthority", false)
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
	database, err := sql.Open("pgx", settings.DatabaseURL)
	if err != nil {
		logger.Error("database rejected", "error_class", "database_unavailable")
		os.Exit(2)
	}
	defer database.Close()
	database.SetMaxOpenConns(settings.DatabaseMaxOpen)
	database.SetMaxIdleConns(settings.DatabaseMaxIdle)
	database.SetConnMaxLifetime(settings.DatabaseConnTTL)
	store, err := factorytime.NewPostgresStore(database,
		settings.DatabaseOperationTimeout)
	if err == nil {
		err = store.VerifySchema()
	}
	if err != nil {
		logger.Error("trusted-time ledger rejected",
			"error_class", "database_unavailable")
		os.Exit(2)
	}
	signer, err := factorytime.LoadRemoteSigner(factorytime.RemoteSignerFiles{
		Endpoint: settings.SignerEndpoint, KeyID: settings.SignerKeyID,
		PublicKeyFile:           settings.SignerPublicKeyFile,
		PublicKeySHA256:         settings.SignerPublicKeySHA256,
		CACertificateFile:       settings.SignerCACertificateFile,
		CACertificateSHA256:     settings.SignerCACertificateSHA256,
		ClientCertificateFile:   settings.SignerClientCertificateFile,
		ClientCertificateSHA256: settings.SignerClientCertificateSHA256,
		ClientPrivateKeyFile:    settings.SignerClientPrivateKeyFile,
		Timeout:                 settings.SignerTimeout,
	})
	if err != nil {
		logger.Error("external signer rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	if err := signer.WrapTransport(func(base http.RoundTripper) (http.RoundTripper, error) {
		return traceRuntime.WrapTransport("factory.signer", base)
	}); err != nil {
		logger.Error("external signer telemetry rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	if err := signer.Ready(context.Background()); err != nil {
		logger.Error("external signer unavailable",
			"error_class", "signer_unavailable")
		os.Exit(2)
	}
	authority, err := factorytime.NewAuthority(store, signer,
		settings.ReceiptLifetime)
	if err != nil {
		logger.Error("trusted-time authority rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	handler, err := factorytime.NewHandler(authority)
	if err != nil {
		logger.Error("trusted-time handler rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	tlsConfiguration, err := factorytime.LoadMTLSServerConfig(
		settings.StationClientCAFile, settings.ServerCertificateFile,
		settings.ServerPrivateKeyFile)
	if err != nil {
		logger.Error("server identity rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	probeHandler, err := factorytime.NewProbeHandler(store, signer)
	if err != nil {
		logger.Error("probe handler rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.Handle("POST "+factorytime.EndpointPath, handler)
	server := &http.Server{
		Addr: settings.ListenAddress, Handler: traceRuntime.WrapHandler(mux),
		TLSConfig:         tlsConfiguration,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      4 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	probeServer := &http.Server{
		Addr: settings.HealthAddress, Handler: probeHandler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    4 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	listener, err := net.Listen("tcp", settings.ListenAddress)
	if err != nil {
		logger.Error("listener rejected", "error_class", "transport_failure")
		os.Exit(1)
	}
	defer listener.Close()
	probeListener, err := net.Listen("tcp", settings.HealthAddress)
	if err != nil {
		logger.Error("probe listener rejected", "error_class", "transport_failure")
		os.Exit(1)
	}
	defer probeListener.Close()
	secureListener := tls.NewListener(listener, tlsConfiguration)
	type serveResult struct {
		name string
		err  error
	}
	serveResults := make(chan serveResult, 2)
	go func() {
		serveResults <- serveResult{name: "authority", err: server.Serve(secureListener)}
	}()
	go func() {
		serveResults <- serveResult{name: "probe", err: probeServer.Serve(probeListener)}
	}()
	logger.Info("factory trusted-time authority ready",
		"probe_address", settings.HealthAddress,
		"signer_key_id", settings.SignerKeyID)
	signalContext, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	exitCode := 0
	select {
	case <-signalContext.Done():
	case result := <-serveResults:
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			logger.Error(result.name+" server stopped",
				"error_class", "transport_failure")
		} else {
			logger.Error(result.name+" server stopped unexpectedly",
				"error_class", "transport_failure")
		}
		exitCode = 1
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(),
		settings.ShutdownTimeout)
	defer cancel()
	if err := probeServer.Shutdown(shutdownContext); err != nil {
		logger.Error("probe graceful shutdown failed",
			"error_class", "shutdown_timeout")
		exitCode = 1
	}
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed",
			"error_class", "shutdown_timeout")
		exitCode = 1
	}
	if err := traceRuntime.Shutdown(shutdownContext); err != nil {
		logger.Error("telemetry shutdown failed",
			"error_class", "shutdown_timeout")
		exitCode = 1
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
