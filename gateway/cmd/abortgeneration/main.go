package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/generation"
)

func main() {
	coordinator := flag.String("coordinator", "", "generation coordinator base URL")
	publisherID := flag.String("publisher-id", "", "configured publisher identity")
	insecure := flag.Bool("allow-insecure-development", false, "allow HTTP for local testing only")
	flag.Parse()
	if flag.NArg() != 0 || *coordinator == "" || *publisherID == "" {
		fmt.Fprintln(os.Stderr, "coordinator and publisher-id are required")
		os.Exit(2)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state, err := client.GetState(ctx)
	if err != nil || state.Phase != generation.PhasePreparing || state.Pending == nil {
		fmt.Fprintln(os.Stderr, "no abortable PREPARING generation")
		os.Exit(1)
	}
	state, err = client.Abort(ctx, generation.AbortRequest{
		ExpectedRevision: state.Revision, Pending: *state.Pending,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "abort generation:", err)
		os.Exit(1)
	}
	fmt.Printf("generation aborted: revision=%d active=%s sequence=%d\n",
		state.Revision, state.Active.ID, state.Active.Sequence)
}
