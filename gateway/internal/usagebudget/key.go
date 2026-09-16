package usagebudget

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

// LoadDigestKey accepts one canonical unpadded base64url-encoded 32-byte key.
// The file must be private, bounded, regular, and not a symlink.
func LoadDigestKey(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("Agent usage digest key file is required")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil || !linkInfo.Mode().IsRegular() || linkInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Agent usage digest key must be a private regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Agent usage digest key: %w", err)
	}
	defer file.Close()
	openInfo, err := file.Stat()
	if err != nil || !os.SameFile(linkInfo, openInfo) {
		return nil, fmt.Errorf("Agent usage digest key changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(data) > 128 {
		return nil, fmt.Errorf("read Agent usage digest key")
	}
	encoded := strings.TrimSuffix(string(data), "\n")
	if encoded == "" || strings.ContainsAny(encoded, "\r\n \t") {
		return nil, fmt.Errorf("Agent usage digest key encoding is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("Agent usage digest key must encode exactly 32 bytes")
	}
	return decoded, nil
}
