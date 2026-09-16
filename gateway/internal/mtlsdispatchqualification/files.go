package mtlsdispatchqualification

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const maximumDocumentBytes = int64(1 << 20)

func readRegular(path string, maximum int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("path is empty")
	}
	status, err := os.Lstat(path)
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximum || (private && status.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("file mode, type, or size is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(status, opened) {
		return nil, fmt.Errorf("file identity changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("file read is invalid")
	}
	return payload, nil
}

func WriteNew(path string, payload []byte) error {
	if len(payload) == 0 || len(payload) > int(maximumDocumentBytes) {
		return fmt.Errorf("mTLS dispatch qualification output size is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("refusing to overwrite mTLS dispatch qualification output: %w", err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if written, err := file.Write(payload); err != nil || written != len(payload) {
		return fmt.Errorf("write mTLS dispatch qualification output")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync mTLS dispatch qualification output")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close mTLS dispatch qualification output")
	}
	success = true
	return nil
}

func DigestRegularFile(path string, maximum int64) (string, error) {
	payload, err := readRegular(path, maximum, false)
	if err != nil {
		return "", err
	}
	return digest(payload), nil
}

func digest(payload []byte) string {
	value := sha256.Sum256(payload)
	return hex.EncodeToString(value[:])
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
