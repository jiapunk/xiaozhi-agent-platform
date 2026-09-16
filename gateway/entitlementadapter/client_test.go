package entitlementadapter_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/entitlementadapter"
)

type hsmStyleTestSigner struct {
	keyID string
}

func (signer hsmStyleTestSigner) KeyID() string {
	return signer.keyID
}

func (hsmStyleTestSigner) Sign(context.Context, []byte) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

var _ entitlementadapter.Signer = hsmStyleTestSigner{}

func TestPublicSDKConstructsWithoutInternalTypes(t *testing.T) {
	caPEM, certificatePEM, keyPEM := clientIdentityFixture(t)
	transport, err := entitlementadapter.NewMTLSClient(
		caPEM, certificatePEM, keyPEM, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://account.example" + entitlementadapter.ApplyPath
	if !entitlementadapter.ValidEndpoint(endpoint) {
		t.Fatal("fixed entitlement endpoint rejected")
	}
	client, err := entitlementadapter.NewClient(endpoint, transport,
		hsmStyleTestSigner{keyID: "provider-adapter-1"}, 5*time.Minute)
	if err != nil || client == nil {
		t.Fatalf("client=%#v err=%v", client, err)
	}
	if entitlementadapter.APIVersion != 1 ||
		entitlementadapter.UpdateContract !=
			"xz-service-entitlement-update-v1" ||
		entitlementadapter.ContractHeader == "" ||
		entitlementadapter.KeyIDHeader == "" ||
		entitlementadapter.SignatureHeader == "" {
		t.Fatal("public wire constants changed")
	}
}

func TestPublicSDKRejectsUnconstructedTransport(t *testing.T) {
	endpoint := "https://account.example" + entitlementadapter.ApplyPath
	if _, err := entitlementadapter.NewClient(endpoint, nil,
		hsmStyleTestSigner{keyID: "provider-adapter-1"},
		5*time.Minute); err != entitlementadapter.ErrInvalid {
		t.Fatalf("nil transport err=%v", err)
	}
	var client *entitlementadapter.Client
	if _, err := client.Apply(context.Background(), entitlementadapter.Update{}); err != entitlementadapter.ErrInvalid {
		t.Fatalf("nil client err=%v", err)
	}
}

func clientIdentityFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "M86 test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &ca, &ca,
		caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "M86 adapter fixture"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leaf, &ca,
		clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
