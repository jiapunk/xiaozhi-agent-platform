package main

import (
	"flag"
	"fmt"
	"os"

	"xiaozhi-agent-platform/gateway/internal/deploymentbundle"
)

type stringList []string

func (values *stringList) String() string {
	return fmt.Sprint([]string(*values))
}

func (values *stringList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	bundle := flag.String("bundle", "", "path to the approved rollout bundle")
	authority := flag.String("authority", "", "canonical public firmware authority")
	var parents stringList
	var keyrings stringList
	flag.Var(&parents, "parent-bundle",
		"repeat from immediate parent through original staging bundle")
	flag.Var(&keyrings, "approver-keyring",
		"repeat for each trusted historical rollout approver keyring")
	flag.Parse()
	if flag.NArg() != 0 || *bundle == "" || len(parents) == 0 ||
		*authority == "" || len(keyrings) == 0 {
		fmt.Fprintln(os.Stderr,
			"bundle, parent-bundle lineage, authority, and approver-keyring are required")
		os.Exit(2)
	}
	receipt, err := deploymentbundle.ValidateRolloutChain(
		*bundle, []string(parents), []string(keyrings), *authority)
	if err != nil {
		fmt.Fprintln(os.Stderr, "OTA rollout bundle rejected:", err)
		os.Exit(1)
	}
	fmt.Printf("OTA rollout bundle verified: generation=%s sequence=%d action=%s basis_points=%d\n",
		receipt.GenerationID, receipt.GenerationSequence,
		receipt.PromotionAction, receipt.RolloutBasisPoints)
}
