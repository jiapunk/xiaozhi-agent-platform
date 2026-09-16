package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	privatePath := flag.String("private-key-output", "",
		"new PKCS8 Ed25519 private key output")
	publicPath := flag.String("public-key-output", "",
		"new PKIX Ed25519 public key output")
	flag.Parse()
	if *privatePath == "" || *publicPath == "" || *privatePath == *publicPath {
		fatal("distinct private-key-output and public-key-output are required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate Ed25519 identity key: " + err.Error())
	}
	defer clear(privateKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fatal("encode Ed25519 private key: " + err.Error())
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fatal("encode Ed25519 public key: " + err.Error())
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER,
	})
	defer clear(privatePEM)
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER,
	})
	if err := writeNewAtomic(*publicPath, publicPEM, 0o644); err != nil {
		fatal(err.Error())
	}
	if err := writeNewAtomic(*privatePath, privatePEM, 0o600); err != nil {
		_ = os.Remove(*publicPath)
		fatal(err.Error())
	}
	fmt.Println("new Ed25519 device identity signing keypair written")
}

func writeNewAtomic(path string, payload []byte, mode os.FileMode) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing key file: %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect key output: %w", err)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create key temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect key file: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write key file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync key file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close key file: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("publish key file: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return fmt.Errorf("remove key temporary file: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open key directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
