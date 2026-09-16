package main

import (
	"context"
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
	coordinator := flag.String("coordinator", "", "generation coordinator base URL")
	publisherID := flag.String("publisher-id", "", "configured publisher identity")
	bundle := flag.String("bundle", "", "new approved rollout bundle")
	authority := flag.String("authority", "", "canonical public firmware authority")
	insecure := flag.Bool("allow-insecure-development", false, "allow HTTP for local testing only")
	var parents stringList
	var keyrings stringList
	flag.Var(&parents, "parent-bundle", "repeat from immediate parent through staging")
	flag.Var(&keyrings, "approver-keyring", "repeat every required historical keyring")
	flag.Parse()
	if flag.NArg() != 0 || *coordinator == "" || *publisherID == "" ||
		*bundle == "" || *authority == "" || len(parents) == 0 || len(keyrings) == 0 {
		fmt.Fprintln(os.Stderr, "coordinator, publisher-id, bundle, authority, parents, and keyrings are required")
		os.Exit(2)
	}
	receipt, err := deploymentbundle.ValidateRolloutChain(*bundle,
		[]string(parents), []string(keyrings), *authority)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rollout bundle rejected:", err)
		os.Exit(1)
	}
	identity, err := generation.LoadBundleGeneration(*bundle)
	if err != nil || identity.ID != receipt.GenerationID ||
		identity.Sequence != receipt.GenerationSequence {
		fmt.Fprintln(os.Stderr, "rollout generation identity rejected:", err)
		os.Exit(1)
	}
	key, err := generation.DecodeHMACKey("GENERATION_PUBLISHER_HMAC_KEY_B64",
		os.Getenv("GENERATION_PUBLISHER_HMAC_KEY_B64"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	client, err := generation.NewClient(*coordinator, generation.Principal{
		ID: *publisherID, Role: "publisher", Key: key,
	}, nil, *insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	state, err := client.GetState(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read coordinator state:", err)
		os.Exit(1)
	}
	if state.Phase != generation.PhaseStable ||
		receipt.ParentGenerationID != state.Active.ID ||
		receipt.ParentGenerationSequence != state.Active.Sequence ||
		receipt.ParentReceiptSHA256 != state.Active.ReceiptSHA256 {
		fmt.Fprintln(os.Stderr, "rollout parent does not match coordinator active CAS")
		os.Exit(1)
	}
	state, err = client.Publish(ctx, generation.PublishRequest{
		ExpectedRevision: state.Revision, ExpectedActive: state.Active,
		Pending: identity,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish generation:", err)
		os.Exit(1)
	}
	fmt.Printf("generation published: revision=%d phase=%s pending=%s sequence=%d\n",
		state.Revision, state.Phase, identity.ID, identity.Sequence)
}
