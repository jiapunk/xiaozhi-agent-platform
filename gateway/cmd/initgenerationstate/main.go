package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/deploymentbundle"
	"xiaozhi-agent-platform/gateway/internal/generation"
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }
func (values *stringList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	stateDirectory := flag.String("state-directory", "", "new private coordinator state directory")
	bundle := flag.String("bundle", "", "fully validated initial immutable bundle")
	authority := flag.String("authority", "", "canonical public firmware authority")
	replicaRegistry := flag.String("replica-registry", "", "canonical replica registry")
	var parents stringList
	var keyrings stringList
	flag.Var(&parents, "parent-bundle", "repeat from immediate parent through staging")
	flag.Var(&keyrings, "approver-keyring", "repeat every required historical keyring")
	flag.Parse()
	if flag.NArg() != 0 || *stateDirectory == "" || *bundle == "" ||
		*authority == "" || *replicaRegistry == "" {
		fmt.Fprintln(os.Stderr, "state-directory, bundle, authority, and replica-registry are required")
		os.Exit(2)
	}
	key, err := generation.DecodeHMACKey("GENERATION_STATE_HMAC_KEY_B64",
		os.Getenv("GENERATION_STATE_HMAC_KEY_B64"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	identity, err := generation.LoadBundleGeneration(*bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initial generation rejected:", err)
		os.Exit(1)
	}
	if identity.Sequence == 0 {
		if len(parents) != 0 || len(keyrings) != 0 {
			fmt.Fprintln(os.Stderr, "staging initialization must not provide rollout ancestry")
			os.Exit(2)
		}
		if _, err := deploymentbundle.Validate(*bundle, *authority); err != nil {
			fmt.Fprintln(os.Stderr, "initial staging bundle rejected:", err)
			os.Exit(1)
		}
	} else {
		if len(parents) == 0 || len(keyrings) == 0 {
			fmt.Fprintln(os.Stderr, "rollout initialization requires complete parent and keyring history")
			os.Exit(2)
		}
		receipt, err := deploymentbundle.ValidateRolloutChain(*bundle,
			[]string(parents), []string(keyrings), *authority)
		if err != nil || receipt.GenerationID != identity.ID ||
			receipt.GenerationSequence != identity.Sequence {
			fmt.Fprintln(os.Stderr, "initial rollout bundle rejected:", err)
			os.Exit(1)
		}
	}
	registry, err := generation.LoadReplicaRegistry(*replicaRegistry)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replica registry rejected:", err)
		os.Exit(1)
	}
	store, err := generation.InitializeStore(*stateDirectory, key, identity,
		registry.References(), time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "generation state initialization failed:", err)
		os.Exit(1)
	}
	defer store.Close()
	state, digest := store.Snapshot()
	fmt.Printf("generation state initialized: revision=%d active=%s sequence=%d record_sha256=%s\n",
		state.Revision, state.Active.ID, state.Active.Sequence, digest)
}
