package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

func main() {
	inputPath := flag.String("input", "", "unsigned version 2 identity JSON")
	privateKeyPath := flag.String("private-key", "", "Ed25519 private key file")
	signingKeyID := flag.String("signing-key-id", "", "trusted signing key identifier")
	outputPath := flag.String("output", "", "signed confidential snapshot output")
	flag.Parse()
	if *inputPath == "" || *privateKeyPath == "" || *signingKeyID == "" ||
		*outputPath == "" {
		fatal("input, private-key, signing-key-id, and output are required")
	}
	input, err := os.Open(*inputPath)
	if err != nil {
		fatal("open unsigned identity snapshot: " + err.Error())
	}
	defer input.Close()
	privateKey, err := provisioning.LoadEd25519PrivateKey(*privateKeyPath)
	if err != nil {
		fatal(err.Error())
	}
	defer clear(privateKey)
	signed, err := provisioning.SignRegistrySnapshot(input, *signingKeyID,
		privateKey, time.Now().UTC())
	if err != nil {
		fatal(err.Error())
	}
	if err := writeAtomic(*outputPath, signed); err != nil {
		fatal(err.Error())
	}
	fmt.Println("signed device identity snapshot written")
}

func writeAtomic(path string, payload []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create identity snapshot temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect identity snapshot: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write identity snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync identity snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close identity snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish identity snapshot: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open identity snapshot directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync identity snapshot directory: %w", err)
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
