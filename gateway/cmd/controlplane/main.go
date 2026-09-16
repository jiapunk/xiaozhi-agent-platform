package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/controlplane"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/identityruntime"
	"xiaozhi-agent-platform/gateway/internal/mtlsdispatchqualification"
	productota "xiaozhi-agent-platform/gateway/internal/ota"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
	"xiaozhi-agent-platform/gateway/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) > 1 {
		if os.Args[1] != "qualify-mtls-dispatch" ||
			runMTLSDispatchQualification(os.Args[2:]) != nil {
			logger.Error("control-plane mode rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		logger.Info("mTLS dispatch observation published")
		return
	}
	settings, err := controlplane.LoadSettings()
	if err != nil {
		logger.Error("configuration rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	traceSettings, err := telemetry.LoadSettings("controlplane", settings.AllowInsecure)
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
	registry, identityUpdater, err := identityruntime.Load(context.Background(),
		settings.Identity, provisioning.ProofSnapshotPurpose, time.Now)
	if err != nil {
		logger.Error("device registry rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	sessionProof, err := provisioning.NewScopedProofVerifier(registry,
		provisioning.SessionProofScope, settings.ProofMaxSkew,
		settings.ProofMinInterval)
	if err != nil {
		logger.Error("session proof verifier rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	agentProof, err := provisioning.NewScopedProofVerifier(registry,
		provisioning.AgentTokenProofScope, settings.ProofMaxSkew,
		settings.ProofMinInterval)
	if err != nil {
		logger.Error("Agent proof verifier rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	voiceIssuer, err := newTokenIssuer(settings.VoiceTokenKeyring,
		settings.VoiceTokenKey, settings.VoiceTokenTTL, auth.VoiceAudience)
	if err != nil {
		logger.Error("voice issuer rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	agentIssuer, err := newTokenIssuer(settings.AgentTokenKeyring,
		settings.AgentTokenKey, settings.AgentTokenTTL, auth.AgentAudience)
	if err != nil {
		logger.Error("Agent issuer rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	var claimProof *provisioning.ProofVerifier
	var appVerifier auth.AuthorizationVerifier
	var companionStatus auth.CompanionStatusAuthorizer
	var serviceEntitlements accountauth.ServiceEntitlementAuthorizer
	var claimStore deviceclaim.OwnershipStore
	var actionConsentStore actionconsent.DecisionStore
	var actionConsentNotifier *actionconsent.WakeNotifier
	var actionConsentChallengeProof *provisioning.ProofVerifier
	var actionConsentResultProof *provisioning.ProofVerifier
	var ownershipDB *sql.DB
	if settings.DeviceClaimEnabled {
		claimProof, err = provisioning.NewScopedProofVerifier(registry,
			provisioning.DeviceClaimProofScope, settings.ProofMaxSkew,
			settings.ProofMinInterval)
		if err != nil {
			logger.Error("device claim proof verifier rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		if len(settings.AppTokenEd25519Keys) != 0 {
			appVerifier, err = auth.NewCompanionJWTVerifier(
				settings.AppTokenEd25519Keys, settings.AppTokenIssuer,
				settings.AppTokenMaxTTL)
		} else {
			appVerifier, err = auth.NewKeyringVerifierForAudience(
				settings.AppTokenKeys, settings.AppTokenMaxTTL,
				auth.CompanionAudience)
		}
		if err != nil {
			logger.Error("Companion App verifier rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		if settings.AppTokenIntrospectionURL != "" {
			introspectionClient, clientErr :=
				auth.LoadCompanionIntrospectionMTLSClient(
					settings.AppTokenIntrospectionCA,
					settings.AppTokenIntrospectionCert,
					settings.AppTokenIntrospectionKey,
					settings.AppTokenIntrospectionTimeout)
			if clientErr == nil {
				introspectionClient.Transport, clientErr =
					traceRuntime.WrapTransport("companion.introspection",
						introspectionClient.Transport)
			}
			if clientErr == nil {
				companionStatus, clientErr = auth.NewCompanionTokenIntrospector(
					settings.AppTokenIntrospectionURL, introspectionClient)
			}
			if clientErr != nil {
				logger.Error("Companion authorization introspection rejected",
					"error_class", "invalid_configuration")
				os.Exit(2)
			}
			if settings.ServiceEntitlementAuthorizationURL != "" {
				entitlementClient, entitlementErr :=
					auth.LoadCompanionIntrospectionMTLSClient(
						settings.AppTokenIntrospectionCA,
						settings.AppTokenIntrospectionCert,
						settings.AppTokenIntrospectionKey,
						settings.AppTokenIntrospectionTimeout)
				if entitlementErr == nil {
					entitlementClient.Transport, entitlementErr =
						traceRuntime.WrapTransport("service.entitlement",
							entitlementClient.Transport)
				}
				if entitlementErr == nil {
					serviceEntitlements, entitlementErr =
						accountauth.NewHTTPServiceEntitlementAuthorizer(
							settings.ServiceEntitlementAuthorizationURL,
							entitlementClient)
				}
				if entitlementErr != nil {
					logger.Error("service entitlement authorization rejected",
						"error_class", "invalid_configuration")
					os.Exit(2)
				}
			}
		}
		if settings.OwnershipDatabaseURL != "" {
			ownershipDB, err = sql.Open("pgx", settings.OwnershipDatabaseURL)
			if err == nil {
				ownershipDB.SetMaxOpenConns(settings.OwnershipDatabaseMax)
				ownershipDB.SetMaxIdleConns(settings.OwnershipDatabaseIdle)
				ownershipDB.SetConnMaxLifetime(settings.OwnershipDatabaseConnTTL)
				var postgresStore *deviceclaim.PostgresStore
				postgresStore, err = deviceclaim.NewPostgresStore(ownershipDB,
					settings.DeviceClaimTTL, settings.DeviceClaimMaxPending,
					settings.OwnershipDatabaseTimeout)
				if err == nil {
					err = postgresStore.VerifySchema()
					claimStore = postgresStore
				}
			}
			if err != nil {
				logger.Error("PostgreSQL ownership store rejected",
					"error_class", "invalid_configuration")
				os.Exit(2)
			}
			defer ownershipDB.Close()
		} else {
			claimStore, err = deviceclaim.NewStore(
				settings.DeviceClaimTTL, settings.DeviceClaimMaxPending)
			if err != nil {
				logger.Error("device claim store rejected",
					"error_class", "invalid_configuration")
				os.Exit(2)
			}
		}
		if settings.ActionConsentEnabled {
			actionConsentChallengeProof, err = provisioning.NewScopedProofVerifier(
				registry, provisioning.ActionConsentChallengeProofScope,
				settings.ProofMaxSkew, 0)
			if err == nil {
				actionConsentResultProof, err = provisioning.NewScopedProofVerifier(
					registry, provisioning.ActionConsentResultProofScope,
					settings.ProofMaxSkew, 0)
			}
			if err != nil {
				logger.Error("action consent device proof verifier rejected",
					"error_class", "invalid_configuration")
				os.Exit(2)
			}
			if settings.ActionConsentReference {
				actionConsentStore, err = actionconsent.NewStore(
					settings.ActionConsentMaxPending)
			} else {
				var postgresConsents *actionconsent.PostgresStore
				postgresConsents, err = actionconsent.NewPostgresStore(ownershipDB,
					settings.ActionConsentMaxPending,
					settings.OwnershipDatabaseTimeout)
				if err == nil {
					err = postgresConsents.VerifySchema()
					actionConsentStore = postgresConsents
				}
			}
			if err != nil {
				logger.Error("action consent store rejected",
					"error_class", "invalid_configuration")
				os.Exit(2)
			}
			if settings.ActionConsentPushEnabled {
				outbox, ok := actionConsentStore.(actionconsent.WakeOutbox)
				if !ok {
					logger.Error("action consent wake outbox rejected",
						"error_class", "invalid_configuration")
					os.Exit(2)
				}
				wakeHTTPClient, wakeErr :=
					auth.LoadCompanionIntrospectionMTLSClient(
						settings.AppTokenIntrospectionCA,
						settings.AppTokenIntrospectionCert,
						settings.AppTokenIntrospectionKey,
						settings.AppTokenIntrospectionTimeout)
				if wakeErr == nil {
					wakeHTTPClient.Timeout = settings.ActionConsentPushTimeout
					wakeHTTPClient.Transport, wakeErr =
						traceRuntime.WrapTransport("companion.wake",
							wakeHTTPClient.Transport)
				}
				var wakeSender *pushdelivery.MTLSWakeClient
				if wakeErr == nil {
					wakeSender, wakeErr = pushdelivery.NewMTLSWakeClient(
						companionAuthority(settings.AppTokenIntrospectionURL),
						wakeHTTPClient)
				}
				if wakeErr == nil {
					actionConsentNotifier, wakeErr = actionconsent.NewWakeNotifier(
						outbox, wakeSender, settings.ActionConsentPushWorkerID,
						settings.ActionConsentPushLease,
						settings.ActionConsentPushRetry)
				}
				if wakeErr != nil {
					logger.Error("action consent wake delivery rejected",
						"error_class", "invalid_configuration")
					os.Exit(2)
				}
			}
		}
	}
	var otaProof *provisioning.ProofVerifier
	var otaRegistry *productota.Registry
	var otaIssuer *auth.Issuer
	var generationGate generation.ServingGate
	var replicaGuard *generation.ReplicaGuard
	if settings.OTAReleaseRegistryFile != "" {
		if err := generation.VerifyControlBundle(settings.Generation.BundleRoot,
			settings.OTAReleaseRegistryFile); err != nil {
			logger.Error("OTA generation registry binding rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		identity, err := generation.LoadBundleGeneration(
			settings.Generation.BundleRoot)
		if err != nil {
			logger.Error("OTA generation receipt rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		generationTransport, transportErr := traceRuntime.WrapTransport(
			"generation.coordinator", http.DefaultTransport)
		if transportErr != nil {
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
		replicaGuard, err = generation.NewReplicaGuard(generationClient, identity)
		if err != nil {
			logger.Error("generation replica guard rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		generationGate = replicaGuard
		otaRegistry, err = productota.LoadRegistry(settings.OTAReleaseRegistryFile)
		if err != nil {
			logger.Error("OTA release registry rejected", "error_class", "invalid_configuration")
			os.Exit(2)
		}
		otaProof, err = provisioning.NewScopedProofVerifier(registry,
			provisioning.OTAOfferProofScope, settings.ProofMaxSkew,
			settings.ProofMinInterval)
		if err != nil {
			logger.Error("OTA proof verifier rejected", "error_class", "invalid_configuration")
			os.Exit(2)
		}
		otaIssuer, err = newTokenIssuer(settings.OTATokenKeyring,
			settings.OTATokenKey, settings.OTATokenTTL, auth.OTAAudience)
		if err != nil {
			logger.Error("OTA issuer rejected", "error_class", "invalid_configuration")
			os.Exit(2)
		}
	}
	var runtimeCoordinator runtimecoordination.Coordinator
	if ownershipDB != nil {
		postgresCoordinator, coordinatorErr :=
			runtimecoordination.NewPostgresCoordinator(ownershipDB,
				os.Getenv("RUNTIME_COORDINATION_WORKER_ID"),
				settings.OwnershipDatabaseTimeout)
		if coordinatorErr == nil {
			coordinatorErr = postgresCoordinator.VerifySchema(context.Background())
		}
		if coordinatorErr == nil {
			for _, proof := range []*provisioning.ProofVerifier{
				sessionProof, agentProof, claimProof, actionConsentChallengeProof,
				actionConsentResultProof, otaProof,
			} {
				if proof != nil {
					coordinatorErr = proof.SetCoordinator(postgresCoordinator)
					if coordinatorErr != nil {
						break
					}
				}
			}
		}
		if coordinatorErr != nil {
			logger.Error("runtime coordinator rejected",
				"error_class", "invalid_configuration")
			os.Exit(2)
		}
		runtimeCoordinator = postgresCoordinator
	} else if !settings.AllowInsecure {
		logger.Error("runtime coordinator is required",
			"error_class", "invalid_configuration")
		os.Exit(2)
	}
	control, err := controlplane.New(controlplane.Config{
		SessionProof: sessionProof, AgentProof: agentProof,
		VoiceIssuer: voiceIssuer, AgentIssuer: agentIssuer,
		OTAProof: otaProof, OTARegistry: otaRegistry, OTAIssuer: otaIssuer,
		OTARolloutKey:   settings.OTARolloutKey,
		GenerationGate:  generationGate,
		PublicDeviceWSS: settings.PublicDeviceWSS, Logger: logger,
		ClaimProof: claimProof, AppVerifier: appVerifier,
		CompanionStatus: companionStatus,
		ClaimStore:      claimStore, Ownership: claimStore,
		ActionConsents:              actionConsentStore,
		ActionConsentChallengeProof: actionConsentChallengeProof,
		ActionConsentResultProof:    actionConsentResultProof,
		RuntimeCoordinator:          runtimeCoordinator,
		ServiceEntitlements:         serviceEntitlements,
		RequireServiceEntitlement:   settings.ServiceEntitlementAuthorizationURL != "",
	})
	if err != nil {
		logger.Error("control plane rejected", "error_class", "invalid_configuration")
		os.Exit(2)
	}
	server := &http.Server{
		Addr: settings.Address, Handler: traceRuntime.WrapHandler(control.Handler()),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 75 * time.Second,
		MaxHeaderBytes: 16 * 1024,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if replicaGuard != nil {
		go replicaGuard.Run(ctx)
	}
	if actionConsentNotifier != nil {
		go func() {
			_ = actionConsentNotifier.Run(ctx, settings.ActionConsentPushPoll,
				func(result actionconsent.WakeRunResult, wakeErr error) {
					if wakeErr != nil {
						logger.Warn("action consent wake delivery deferred",
							"result", uint8(result),
							"error_class", "wake_delivery_unavailable")
						return
					}
					logger.Info("action consent wake delivery completed",
						"result", uint8(result))
				})
		}()
	}
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
			})
	}
	errChannel := make(chan error, 1)
	go func() {
		logger.Info("control plane starting", "address", settings.Address,
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
			logger.Error("control plane shutdown failed",
				"error_class", "shutdown_failed")
			os.Exit(1)
		}
	case err := <-errChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("control plane stopped", "error_class", "server_failed")
			os.Exit(1)
		}
	}
	traceShutdownContext, traceCancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	if err := traceRuntime.Shutdown(traceShutdownContext); err != nil {
		logger.Error("telemetry shutdown failed", "error_class", "shutdown_failed")
	}
	traceCancel()
	logger.Info("control plane stopped")
}

func newTokenIssuer(keyring *auth.ManagedTokenKeyring, legacyKey []byte,
	ttl time.Duration, audience string) (*auth.Issuer, error) {
	if keyring != nil {
		return auth.NewManagedIssuerForAudience(keyring, ttl, audience)
	}
	return auth.NewIssuerForAudience(legacyKey, ttl, audience)
}

func runMTLSDispatchQualification(arguments []string) error {
	flags := flag.NewFlagSet("qualify-mtls-dispatch", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "private live qualification config")
	outputPath := flags.String("output", "", "new canonical observation")
	requestTimeout := flags.Duration("request-timeout", 2*time.Second,
		"private wake request timeout")
	acknowledge := flags.Bool("acknowledge-live-mtls-dispatch", false,
		"acknowledge live current/next and negative TLS probes")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		*configPath == "" || *outputPath == "" || !*acknowledge {
		return fmt.Errorf("complete mTLS dispatch qualification arguments are required")
	}
	config, err := mtlsdispatchqualification.LoadLiveConfig(
		*configPath, *requestTimeout)
	if err != nil {
		return fmt.Errorf("mTLS dispatch qualification config rejected")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("control-plane executable identity unavailable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("control-plane executable identity unavailable")
	}
	config.ToolSHA256, err = mtlsdispatchqualification.DigestRegularFile(
		executable, 256*1024*1024)
	if err != nil {
		return fmt.Errorf("control-plane executable identity rejected")
	}
	runContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	observation, err := mtlsdispatchqualification.NewRunner().Run(
		runContext, config)
	if err != nil {
		return fmt.Errorf("live mTLS dispatch qualification failed")
	}
	payload, err := mtlsdispatchqualification.CanonicalObservation(observation)
	if err != nil {
		return fmt.Errorf("mTLS dispatch observation serialization failed")
	}
	if err := mtlsdispatchqualification.WriteNew(*outputPath, payload); err != nil {
		return fmt.Errorf("mTLS dispatch observation publication failed")
	}
	return nil
}

func companionAuthority(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
