package identityruntime

import (
	"context"
	"fmt"
	"time"

	"xiaozhi-agent-platform/gateway/internal/identityconfig"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

// Load constructs the common registry and updater selected by service
// configuration. Remote mode performs a synchronous mTLS fetch so no service
// becomes ready before it has an independently signed snapshot.
func Load(ctx context.Context, settings identityconfig.Settings,
	purpose string, now func() time.Time) (*provisioning.Registry,
	provisioning.RegistryUpdater, error) {
	if !settings.Configured() {
		return nil, nil, nil
	}
	if purpose != provisioning.AccessSnapshotPurpose &&
		purpose != provisioning.ProofSnapshotPurpose {
		return nil, nil, fmt.Errorf("device identity purpose is invalid")
	}
	if settings.Remote() {
		client, err := provisioning.NewIdentityMTLSClient(
			settings.TLSCAFile, settings.TLSCertificateFile,
			settings.TLSKeyFile, settings.RequestTimeout)
		if err != nil {
			return nil, nil, err
		}
		registry, updater, err := provisioning.LoadRemoteReloadableRegistry(
			ctx, settings.URL, settings.SigningPublicKeyFile,
			settings.SigningKeyID, purpose, settings.MinimumRevision,
			client, now)
		return registry, updater, err
	}
	if settings.Signed() {
		registry, updater, err := provisioning.LoadReloadableRegistry(
			settings.File, settings.SigningPublicKeyFile,
			settings.SigningKeyID, purpose, settings.MinimumRevision, now)
		return registry, updater, err
	}
	registry, err := provisioning.LoadRegistry(settings.File)
	return registry, nil, err
}
