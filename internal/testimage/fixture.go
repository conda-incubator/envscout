// Package testimage builds small offline OCI fixtures for cross-package tests.
package testimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type Entry struct {
	Name, Data string
	Type       byte
	Link       string
}

func Archive(t *testing.T, layers ...[]Entry) string {
	t.Helper()
	return ArchivePlatform(t, "linux", "amd64", layers...)
}

func ArchivePlatform(t *testing.T, osName, architecture string, layers ...[]Entry) string {
	t.Helper()
	return ArchiveVariant(t, osName, architecture, "", layers...)
}

func ArchiveVariant(t *testing.T, osName, architecture, variant string, layers ...[]Entry) string {
	t.Helper()
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	blob := func(data []byte, mediaType types.MediaType) v1.Descriptor {
		hash := sha256.Sum256(data)
		digest := v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(hash[:])}
		files["blobs/sha256/"+digest.Hex] = data
		return v1.Descriptor{Digest: digest, Size: int64(len(data)), MediaType: mediaType}
	}
	config := v1.ConfigFile{OS: osName, Architecture: architecture, Variant: variant, RootFS: v1.RootFS{Type: "layers"}}
	manifest := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1}
	for _, entries := range layers {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		for _, entry := range entries {
			kind := entry.Type
			if kind == 0 {
				kind = tar.TypeReg
			}
			size := int64(0)
			if kind == tar.TypeReg {
				size = int64(len(entry.Data))
			}
			if err := tw.WriteHeader(&tar.Header{Name: entry.Name, Mode: 0o644, Typeflag: kind, Size: size, Linkname: entry.Link}); err != nil {
				t.Fatal(err)
			}
			if size > 0 {
				if _, err := tw.Write([]byte(entry.Data)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		diff := sha256.Sum256(raw.Bytes())
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(diff[:])})
		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		if _, err := gw.Write(raw.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		manifest.Layers = append(manifest.Layers, blob(compressed.Bytes(), types.OCILayer))
	}
	encode := func(value any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	manifest.Config = blob(encode(config), types.OCIConfigJSON)
	desc := blob(encode(manifest), types.OCIManifestSchema1)
	desc.Platform = &v1.Platform{OS: osName, Architecture: architecture, Variant: variant}
	files["index.json"] = encode(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{desc}})
	archive := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(files[name]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return archive
}
