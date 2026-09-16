package firmwareorigin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	maximumCatalogBytes = 1024 * 1024
	maximumObjects      = 64
	maximumImageBytes   = int64(2147483647)
	maximumPathBytes    = 512
)

type catalogEntry struct {
	ReleaseID   string `json:"release_id"`
	ImageSHA256 string `json:"image_sha256"`
	ImageSize   int64  `json:"image_size"`
	URLPath     string `json:"url_path"`
	ImageFile   string `json:"image_file"`
}

type catalogDocument struct {
	Version int            `json:"version"`
	Objects []catalogEntry `json:"objects"`
}

type Object struct {
	ReleaseID   string
	ImageSHA256 string
	ImageSize   int64
	URLPath     string
	imageFile   string
}

type Catalog struct {
	byPath  map[string]Object
	objects []Object
}

func LoadCatalog(catalogPath string) (*Catalog, error) {
	if catalogPath == "" {
		return nil, fmt.Errorf("firmware origin catalog path is required")
	}
	payload, err := readBoundedFile(catalogPath, maximumCatalogBytes)
	if err != nil {
		return nil, fmt.Errorf("read firmware origin catalog: %w", err)
	}
	if err := rejectDuplicateJSONNames(payload); err != nil {
		return nil, fmt.Errorf("firmware origin catalog JSON: %w", err)
	}
	var document catalogDocument
	if err := decodeStrict(payload, &document); err != nil {
		return nil, fmt.Errorf("decode firmware origin catalog: %w", err)
	}
	if document.Version != 1 || len(document.Objects) == 0 ||
		len(document.Objects) > maximumObjects {
		return nil, fmt.Errorf("firmware origin catalog version/count is invalid")
	}

	root, err := filepath.Abs(filepath.Dir(catalogPath))
	if err != nil {
		return nil, fmt.Errorf("resolve firmware origin catalog root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve firmware origin catalog root: %w", err)
	}
	catalog := &Catalog{
		byPath:  make(map[string]Object, len(document.Objects)),
		objects: make([]Object, 0, len(document.Objects)),
	}
	seenRelease := make(map[string]struct{}, len(document.Objects))
	for _, entry := range document.Objects {
		if !auth.ValidIdentifier(entry.ReleaseID, 64) ||
			!validSHA256(entry.ImageSHA256) || entry.ImageSize < 1024 ||
			entry.ImageSize > maximumImageBytes || !validURLPath(entry.URLPath) ||
			entry.ImageFile == "" || len(entry.ImageFile) > 4096 {
			return nil, fmt.Errorf("firmware origin object fields are invalid")
		}
		if _, exists := seenRelease[entry.ReleaseID]; exists {
			return nil, fmt.Errorf("firmware origin release ID is duplicated")
		}
		if _, exists := catalog.byPath[entry.URLPath]; exists {
			return nil, fmt.Errorf("firmware origin URL path is duplicated")
		}
		imageFile, err := resolveContainedFile(resolvedRoot, entry.ImageFile)
		if err != nil {
			return nil, fmt.Errorf("resolve firmware origin image: %w", err)
		}
		object := Object{
			ReleaseID: entry.ReleaseID, ImageSHA256: entry.ImageSHA256,
			ImageSize: entry.ImageSize, URLPath: entry.URLPath,
			imageFile: imageFile,
		}
		file, err := object.OpenVerified()
		if err != nil {
			return nil, fmt.Errorf("verify firmware origin image %q: %w",
				entry.ReleaseID, err)
		}
		_ = file.Close()
		seenRelease[entry.ReleaseID] = struct{}{}
		catalog.byPath[entry.URLPath] = object
		catalog.objects = append(catalog.objects, object)
	}
	return catalog, nil
}

func (catalog *Catalog) Lookup(urlPath string) (Object, bool) {
	if catalog == nil {
		return Object{}, false
	}
	object, found := catalog.byPath[urlPath]
	return object, found
}

func (catalog *Catalog) Ready() error {
	if catalog == nil || len(catalog.objects) == 0 {
		return fmt.Errorf("firmware origin catalog is unavailable")
	}
	for _, object := range catalog.objects {
		info, err := os.Stat(object.imageFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() != object.ImageSize {
			return fmt.Errorf("firmware origin image is unavailable")
		}
	}
	return nil
}

func (object Object) OpenVerified() (*os.File, error) {
	if object.imageFile == "" || !auth.ValidIdentifier(object.ReleaseID, 64) ||
		!validSHA256(object.ImageSHA256) || object.ImageSize < 1024 ||
		object.ImageSize > maximumImageBytes {
		return nil, fmt.Errorf("firmware origin object is invalid")
	}
	file, err := os.Open(object.imageFile)
	if err != nil {
		return nil, err
	}
	valid := false
	defer func() {
		if !valid {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != object.ImageSize {
		return nil, fmt.Errorf("firmware image type/size changed")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, object.ImageSize+1))
	if err != nil || written != object.ImageSize ||
		hex.EncodeToString(hash.Sum(nil)) != object.ImageSHA256 {
		return nil, fmt.Errorf("firmware image hash changed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	valid = true
	return file, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validURLPath(value string) bool {
	if len(value) < 2 || len(value) > maximumPathBytes || value[0] != '/' ||
		path.Clean(value) != value || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "//") || strings.ContainsAny(value, "%\\?#") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '/' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return strings.HasSuffix(value, ".bin")
}

func resolveContainedFile(root, name string) (string, error) {
	if filepath.IsAbs(name) || strings.Contains(name, "\\") {
		return "", fmt.Errorf("image path must be relative")
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || clean != name ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("image path escapes catalog root")
	}
	joined := filepath.Join(root, clean)
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("image symlink escapes catalog root")
	}
	return resolved, nil
}

func readBoundedFile(name string, maximum int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, fmt.Errorf("file size is outside range")
	}
	return payload, nil
}

func decodeStrict(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON has trailing data")
	}
	return nil
}

func rejectDuplicateJSONNames(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return fmt.Errorf("object name is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON name %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("array is not closed")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON has trailing data")
	}
	return nil
}
