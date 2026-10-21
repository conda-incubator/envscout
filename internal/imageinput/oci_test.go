package imageinput

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/testimage"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestLoadOCIAndCleanup(t *testing.T) {
	input := testimage.Archive(t, []testimage.Entry{{Name: "opt/conda/conda-meta/python.json", Data: `{"name":"python","version":"3.12"}`}})
	loaded, err := Load(context.Background(), input, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity.Source != "oci-archive" || !strings.HasPrefix(loaded.Identity.ManifestDigest, "sha256:") || loaded.Identity.OS != "linux" || loaded.Identity.Architecture != "amd64" || loaded.Identity.ConfigDigest == loaded.Identity.ManifestDigest {
		t.Fatalf("incorrect image identity: %+v", loaded.Identity)
	}
	stage := loaded.stage
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("staged layout not removed: %v", err)
	}
	if err := loaded.Close(); err != nil {
		t.Fatalf("second cleanup failed: %v", err)
	}
}

func TestLoadLimitsAndPlatform(t *testing.T) {
	input := testimage.Archive(t, []testimage.Entry{{Name: "large.txt", Data: strings.Repeat("x", 4096)}})
	for _, tt := range []struct {
		name, platform string
		limits         Limits
	}{
		{"archive limit", "linux/amd64", Limits{ArchiveBytes: 1, LayoutBytes: 1 << 20, ExpandedBytes: 1 << 20, Entries: 100, Layers: 10}},
		{"layout limit", "linux/amd64", Limits{ArchiveBytes: 1 << 20, LayoutBytes: 1, ExpandedBytes: 1 << 20, Entries: 100, Layers: 10}},
		{"expansion limit", "linux/amd64", Limits{ArchiveBytes: 1 << 20, LayoutBytes: 1 << 20, ExpandedBytes: 1024, Entries: 100, Layers: 10}},
		{"missing platform", "", DefaultLimits()},
		{"wrong platform", "linux/arm64", DefaultLimits()},
		{"unknown OS", "nonsense/amd64", DefaultLimits()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if loaded, err := LoadWithLimits(context.Background(), input, tt.platform, tt.limits); err == nil {
				_ = loaded.Close()
				t.Fatal("expected rejected image")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, input, "linux/amd64"); err == nil {
		t.Fatal("cancelled load succeeded")
	}
}

func TestLoadRejectsUnsafeArchiveAndCleansStage(t *testing.T) {
	for _, tt := range []struct {
		name string
		h    tar.Header
		data string
	}{
		{"traversal", tar.Header{Name: "../outside", Size: 1}, "x"},
		{"absolute", tar.Header{Name: "/outside", Size: 1}, "x"},
		{"symlink", tar.Header{Name: "blobs", Typeflag: tar.TypeSymlink, Linkname: "../outside"}, ""},
		{"docker save", tar.Header{Name: "manifest.json", Size: 2}, "[]"},
		{"wrong digest", tar.Header{Name: "blobs/sha256/" + strings.Repeat("0", 64), Size: 1}, "x"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A dedicated temp parent makes leaked staging directories observable.
			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			t.Setenv("TMP", parent)
			t.Setenv("TEMP", parent)
			input := filepath.Join(parent, "invalid.tar")
			f, err := os.Create(input)
			if err != nil {
				t.Fatal(err)
			}
			tw := tar.NewWriter(f)
			if err := tw.WriteHeader(&tt.h); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(tt.data)); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if loaded, err := Load(context.Background(), input, "linux/amd64"); err == nil {
				_ = loaded.Close()
				t.Fatal("unsafe archive accepted")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != "invalid.tar" {
				t.Fatalf("load leaked staging directories: %+v, %v", entries, err)
			}
		})
	}
}

func TestMultiPlatformSelectionAndAmbiguity(t *testing.T) {
	amd := testimage.Archive(t, []testimage.Entry{{Name: "amd.txt", Data: "amd64"}})
	arm := testimage.ArchivePlatform(t, "linux", "arm64", []testimage.Entry{{Name: "arm.txt", Data: "arm64"}})
	input := combineArchives(t, amd, arm)
	for _, arch := range []string{"amd64", "arm64"} {
		loaded, err := Load(context.Background(), input, "linux/"+arch)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Identity.Architecture != arch {
			t.Fatalf("wrong selected platform: %+v", loaded.Identity)
		}
		if err := loaded.Close(); err != nil {
			t.Fatal(err)
		}
	}
	otherAMD := testimage.Archive(t, []testimage.Entry{{Name: "different.txt", Data: "different manifest"}})
	ambiguous := combineArchives(t, amd, otherAMD)
	if _, err := Load(context.Background(), ambiguous, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("ambiguous platform should fail: %v", err)
	}
}

func TestARMDefaultVariant(t *testing.T) {
	input := testimage.ArchiveVariant(t, "linux", "arm64", "v8", []testimage.Entry{{Name: "test", Data: "arm64"}})
	for _, platform := range []string{"linux/arm64", "linux/arm64/v8"} {
		loaded, err := Load(context.Background(), input, platform)
		if err != nil {
			t.Fatalf("default ARM variant rejected for %s: %v", platform, err)
		}
		if err := loaded.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLayerPathDepthLimit(t *testing.T) {
	input := testimage.Archive(t, []testimage.Entry{{Name: strings.Repeat("d/", maxLayerPathDepth) + "file", Data: "x"}})
	if _, err := Load(context.Background(), input, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("deep synthetic tree accepted: %v", err)
	}
}

// Merge independent platform fixtures into one index without a container daemon.
func combineArchives(t *testing.T, archives ...string) string {
	t.Helper()
	files := make(map[string][]byte)
	var merged v1.IndexManifest
	for _, archive := range archives {
		data, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if h.Name == "index.json" {
				var index v1.IndexManifest
				if err := json.Unmarshal(content, &index); err != nil {
					t.Fatal(err)
				}
				merged.SchemaVersion, merged.MediaType = index.SchemaVersion, index.MediaType
				merged.Manifests = append(merged.Manifests, index.Manifests...)
			} else {
				files[h.Name] = content
			}
		}
	}
	index, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	files["index.json"] = index
	output := filepath.Join(t.TempDir(), "multi.tar")
	f, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return output
}
