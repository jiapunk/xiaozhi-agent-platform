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

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo}))
	settings, err := accountauth.LoadSettings()
	if err != nil {
		logger.Error("configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings("accountauthorization", false)
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
	ledger, err := accountauth.NewPostgresStore(database, settings.OperationTimeout)
	if err == nil {
		err = ledger.VerifySchema()
	}
	if err != nil {
		logger.Error("authorization ledger rejected",
			"error_class", "database_unavailable")
		os.Exit(2)
	}
	introspection, err := accountauth.NewIntrospectionHandler(ledger)
	if err != nil {
		logger.Error("introspection handler rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	entitlementAuthorization, err :=
		accountauth.NewServiceEntitlementAuthorizationHandler(ledger)
	if err != nil {
		logger.Error("service entitlement handler rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	entitlementUpdateKeyring, err :=
		accountauth.LoadEntitlementUpdateKeyring(
			settings.EntitlementUpdateKeyringFile,
			settings.EntitlementUpdateKeyringMinRevision, time.Now())
	if err != nil {
		logger.Error("service entitlement update trust rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	entitlementUpdate, err := accountauth.NewServiceEntitlementUpdateHandler(
		ledger, entitlementUpdateKeyring,
		settings.EntitlementUpdateAuthorizationTTL)
	if err != nil {
		logger.Error("service entitlement update handler rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	tlsConfiguration, err := accountauth.LoadIntrospectionMTLSServerConfig(
		settings.ClientCAFile, settings.ServerCertFile, settings.ServerKeyFile)
	if err != nil {
		logger.Error("server identity rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	probeHandler, err := accountauth.NewProbeHandler(ledger)
	if err != nil {
		logger.Error("probe handler rejected",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.Handle(authPath(), introspection)
	mux.Handle("POST "+accountauth.ServiceEntitlementAuthorizationPath,
		entitlementAuthorization)
	mux.Handle("POST "+accountauth.ServiceEntitlementUpdatePath,
		entitlementUpdate)
	if settings.PushEnabled {
		wakeHandler, pushErr := buildPushWakeHandler(settings, ledger, traceRuntime)
		if pushErr != nil {
			logger.Error("push delivery rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		mux.Handle("POST "+pushdelivery.PrivateWakePath, wakeHandler)
	}
	server := &http.Server{
		Addr: settings.ListenAddress, Handler: traceRuntime.WrapHandler(mux),
		TLSConfig:         tlsConfiguration,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      accountWriteTimeout(settings),
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	probeServer := &http.Server{
		Addr: settings.HealthAddress, Handler: probeHandler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
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
		serveResults <- serveResult{name: "introspection", err: server.Serve(secureListener)}
	}()
	go func() {
		serveResults <- serveResult{name: "probe", err: probeServer.Serve(probeListener)}
	}()
	logger.Info("Companion authorization introspection ready",
		"probe_address", settings.HealthAddress)
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
	shutdownContext, cancel := context.WithTimeout(
		context.Background(), settings.ShutdownTimeout)
	defer cancel()
	if err := probeServer.Shutdown(shutdownContext); err != nil {
		logger.Error("probe graceful shutdown failed",
			"error_class", "shutdown_timeout")
		exitCode = 1
	}
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Error("graceful shutdown failed", "error_class", "shutdown_timeout")
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

func authPath() string {
	return "POST " + auth.CompanionIntrospectionPath
}

func buildPushWakeHandler(settings accountauth.Settings,
	ledger *accountauth.PostgresStore,
	traceRuntime *telemetry.Runtime) (*pushdelivery.PrivateWakeHandler, error) {
	protector, err := accountauth.LoadPushTokenProtector(
		settings.PushTokenKeyringFile)
	if err != nil {
		return nil, err
	}
	providers := make(map[accountauth.PushPlatform]pushdelivery.Provider, 3)
	if settings.PushAPNsTopic != "" {
		providerClient, clientErr := tracedHTTPClient(traceRuntime, "push.apns",
			newProviderHTTPClient(settings.PushProviderTimeout))
		if clientErr != nil {
			return nil, clientErr
		}
		signer, loadErr := pushdelivery.LoadAPNsPrivateKey(
			settings.PushAPNsPrivateKeyFile)
		if loadErr != nil {
			return nil, loadErr
		}
		bearer, loadErr := pushdelivery.NewAPNsJWTBearerProvider(signer,
			settings.PushAPNsKeyID, settings.PushAPNsTeamID)
		if loadErr != nil {
			return nil, loadErr
		}
		production, loadErr := pushdelivery.NewAPNsProvider(providerClient,
			bearer, settings.PushAPNsTopic, pushdelivery.APNsProduction)
		if loadErr != nil {
			return nil, loadErr
		}
		development, loadErr := pushdelivery.NewAPNsProvider(providerClient,
			bearer, settings.PushAPNsTopic, pushdelivery.APNsDevelopment)
		if loadErr != nil {
			return nil, loadErr
		}
		providers[accountauth.PushPlatformAPNSProduction] = production
		providers[accountauth.PushPlatformAPNSDevelopment] = development
	}
	if settings.PushFCMProjectID != "" {
		var source pushdelivery.OAuthAccessTokenSource
		switch settings.PushFCMCredentialMode {
		case "metadata":
			var metadataClient *http.Client
			metadataClient, err = tracedHTTPClient(traceRuntime, "push.oauth",
				newMetadataHTTPClient(settings.PushProviderTimeout))
			if err == nil {
				source, err = pushdelivery.NewGoogleMetadataTokenSource(metadataClient)
			}
		case "service-account":
			var credential pushdelivery.GoogleServiceAccountCredential
			credential, err = pushdelivery.LoadGoogleServiceAccountCredential(
				settings.PushFCMServiceAccountFile)
			if err == nil && credential.ProjectID != settings.PushFCMProjectID {
				return nil, pushdelivery.ErrInvalid
			}
			if err == nil {
				var oauthClient *http.Client
				oauthClient, err = tracedHTTPClient(traceRuntime, "push.oauth",
					newProviderHTTPClient(settings.PushProviderTimeout))
				if err != nil {
					break
				}
				source, err = pushdelivery.NewGoogleServiceAccountTokenSource(
					oauthClient, credential.Signer, credential.Email,
					credential.KeyID)
			}
		default:
			err = pushdelivery.ErrInvalid
		}
		if err != nil {
			return nil, err
		}
		bearer, err := pushdelivery.NewCachedOAuthBearerProvider(source)
		if err != nil {
			return nil, err
		}
		providerClient, err := tracedHTTPClient(traceRuntime, "push.fcm",
			newProviderHTTPClient(settings.PushProviderTimeout))
		if err != nil {
			return nil, err
		}
		fcm, err := pushdelivery.NewFCMProvider(providerClient, bearer,
			settings.PushFCMProjectID)
		if err != nil {
			return nil, err
		}
		providers[accountauth.PushPlatformFCM] = fcm
	}
	sender, err := pushdelivery.NewWakeSender(ledger, protector, providers)
	if err != nil {
		return nil, err
	}
	return pushdelivery.NewPrivateWakeHandler(sender)
}

func tracedHTTPClient(traceRuntime *telemetry.Runtime, operation string,
	client *http.Client) (*http.Client, error) {
	if traceRuntime == nil || client == nil {
		return nil, errors.New("telemetry HTTP client is invalid")
	}
	transport, err := traceRuntime.WrapTransport(operation, client.Transport)
	if err != nil {
		return nil, err
	}
	client.Transport = transport
	return client, nil
}

func newProviderHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		MaxIdleConns: 16, MaxIdleConnsPerHost: 8,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}}
}

func newMetadataHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy: nil, DisableCompression: true,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 10 * time.Second,
	}}
}

func accountWriteTimeout(settings accountauth.Settings) time.Duration {
	if !settings.PushEnabled {
		return 3 * time.Second
	}
	limit := 2*settings.PushProviderTimeout + 2*time.Second
	if limit > 8*time.Second {
		return 8 * time.Second
	}
	return limit
}
