package entitlementadapter_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSeparateModuleCanImportPublicSDK(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate SDK source")
	}
	moduleRoot := filepath.Dir(filepath.Dir(sourceFile))
	temporary := t.TempDir()
	goMod := "module example.com/selected-provider-adapter\n\n" +
		"go 1.26\n\n" +
		"require xiaozhi-agent-platform/gateway v0.0.0\n\n" +
		"replace xiaozhi-agent-platform/gateway => " +
		filepath.ToSlash(moduleRoot) + "\n"
	consumer := `package provideradapter

import (
	"context"
	"time"

	sdk "xiaozhi-agent-platform/gateway/entitlementadapter"
)

type kmsSigner struct{}

func (kmsSigner) KeyID() string { return "selected-provider-key-1" }
func (kmsSigner) Sign(context.Context, []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

var _ sdk.Signer = kmsSigner{}

func compilePublicSurface(transport *sdk.MTLSClient) (*sdk.Client, error) {
	return sdk.NewClient("https://account.example"+sdk.ApplyPath, transport,
		kmsSigner{}, 5*time.Minute)
}
`
	if err := os.WriteFile(filepath.Join(temporary, "go.mod"),
		[]byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temporary, "adapter_test.go"),
		[]byte(consumer), 0o600); err != nil {
		t.Fatal(err)
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command(goBinary, "test", "-mod=mod", "./...")
	command.Dir = temporary
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("external consumer compile failed: %v\n%s",
			err, strings.TrimSpace(string(output)))
	}
}
