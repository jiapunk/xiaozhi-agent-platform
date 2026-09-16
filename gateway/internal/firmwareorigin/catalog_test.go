package firmwareorigin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCatalogFixture(t *testing.T, image []byte) (*Catalog, string, string) {
	t.Helper()
	directory := t.TempDir()
	imageDirectory := filepath.Join(directory, "images")
	if err := os.Mkdir(imageDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(imageDirectory, "release-15.bin")
	if err := os.WriteFile(imagePath, image, 0o444); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(image)
	hash := hex.EncodeToString(digest[:])
	document := map[string]any{
		"version": 1,
		"objects": []map[string]any{{
			"release_id":   "box3-development-0015",
			"image_sha256": hash,
			"image_size":   len(image),
			"url_path":     "/firmware/box3/0015.bin",
			"image_file":   "images/release-15.bin",
		}},
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(catalogPath, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, imagePath, hash
}

func TestCatalogLoadsAndRevalidatesImmutableObject(t *testing.T) {
	image := []byte(strings.Repeat("firmware-image-", 128))
	catalog, _, hash := writeCatalogFixture(t, image)
	object, found := catalog.Lookup("/firmware/box3/0015.bin")
	if !found || object.ReleaseID != "box3-development-0015" ||
		object.ImageSHA256 != hash || object.ImageSize != int64(len(image)) {
		t.Fatalf("unexpected catalog object: %#v found=%v", object, found)
	}
	file, err := object.OpenVerified()
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err := catalog.Ready(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogRejectsTamperUnknownDuplicateAndUnsafePaths(t *testing.T) {
	image := []byte(strings.Repeat("firmware-image-", 128))
	digest := sha256.Sum256(image)
	hash := hex.EncodeToString(digest[:])
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "image.bin"), image, 0o444); err != nil {
		t.Fatal(err)
	}
	baseObject := `{"release_id":"release-15","image_sha256":"` + hash +
		`","image_size":` + strings.TrimSpace(jsonNumber(len(image))) +
		`,"url_path":"/firmware/release-15.bin","image_file":"image.bin"}`
	cases := map[string]string{
		"unknown":           `{"version":1,"unknown":true,"objects":[` + baseObject + `]}`,
		"duplicate-name":    `{"version":1,"version":1,"objects":[` + baseObject + `]}`,
		"duplicate-release": `{"version":1,"objects":[` + baseObject + `,` + baseObject + `]}`,
		"traversal": `{"version":1,"objects":[{"release_id":"release-15",` +
			`"image_sha256":"` + hash + `","image_size":` + jsonNumber(len(image)) +
			`,"url_path":"/firmware/release-15.bin","image_file":"../image.bin"}]}`,
		"encoded-url": `{"version":1,"objects":[{"release_id":"release-15",` +
			`"image_sha256":"` + hash + `","image_size":` + jsonNumber(len(image)) +
			`,"url_path":"/firmware/%2e%2e/release.bin","image_file":"image.bin"}]}`,
		"wrong-hash": `{"version":1,"objects":[{"release_id":"release-15",` +
			`"image_sha256":"` + strings.Repeat("b", 64) + `","image_size":` +
			jsonNumber(len(image)) + `,"url_path":"/firmware/release-15.bin",` +
			`"image_file":"image.bin"}]}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			catalogPath := filepath.Join(directory, name+".json")
			if err := os.WriteFile(catalogPath, []byte(payload), 0o444); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCatalog(catalogPath); err == nil {
				t.Fatal("expected catalog rejection")
			}
		})
	}
}

func TestCatalogRejectsSymlinkOutsideRoot(t *testing.T) {
	image := []byte(strings.Repeat("firmware-image-", 128))
	digest := sha256.Sum256(image)
	outside := t.TempDir()
	outsideImage := filepath.Join(outside, "outside.bin")
	if err := os.WriteFile(outsideImage, image, 0o444); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(outsideImage, filepath.Join(directory, "link.bin")); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"version": 1,
		"objects": []map[string]any{{
			"release_id":   "release-15",
			"image_sha256": hex.EncodeToString(digest[:]),
			"image_size":   len(image),
			"url_path":     "/firmware/release-15.bin",
			"image_file":   "link.bin",
		}},
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(catalogPath, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(catalogPath); err == nil {
		t.Fatal("catalog accepted a symlink outside its root")
	}
}

func jsonNumber(value int) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}
