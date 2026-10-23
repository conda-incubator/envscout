package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/testimage"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestImageFilename(t *testing.T) {
	manifest := strings.Repeat("a", 64)
	config := strings.Repeat("b", 64)
	for _, tc := range []struct {
		name     string
		metadata image.Metadata
		want     string
	}{
		{
			name: "manifest preferred",
			metadata: image.Metadata{
				ManifestDigest: "sha256:" + manifest, ID: "sha256:" + config,
				OS: "linux", Architecture: "arm64", Variant: "v8",
			},
			want: "image-manifest-sha256-" + manifest + "-linux-arm64-v8.cdx.json",
		},
		{
			name: "config fallback",
			metadata: image.Metadata{
				ID: "sha256:" + config, OS: "linux", Architecture: "amd64",
			},
			want: "image-config-sha256-" + config + "-linux-amd64.cdx.json",
		},
		{
			name: "platform escaped",
			metadata: image.Metadata{
				ManifestDigest: "sha256:" + manifest,
				OS:             "../linux", Architecture: "arm/64", Variant: `v\8`,
			},
			want: "image-manifest-sha256-" + manifest + "-..%2Flinux-arm%2F64-v%5C8.cdx.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := imageFilename(&image.Image{Metadata: tc.metadata})
			if err != nil || got != tc.want {
				t.Fatalf("imageFilename = %q, %v; want %q", got, err, tc.want)
			}
			if strings.ContainsAny(got, `/\`) {
				t.Fatalf("filename contains a path separator: %q", got)
			}
		})
	}
	for _, digest := range []string{"", "sha256:abc", "sha256:" + strings.Repeat("z", 64), "sha512:" + manifest} {
		t.Run("invalid "+digest, func(t *testing.T) {
			if _, err := imageFilename(&image.Image{Metadata: image.Metadata{ManifestDigest: digest}}); err == nil {
				t.Fatal("expected invalid digest error")
			}
		})
	}
}

func TestResultForSBOM(t *testing.T) {
	conda := pkg.Package{Name: "python", Version: "3.12", Type: pkg.CondaPkg}
	bom := &sbom.SBOM{
		Descriptor: sbom.Descriptor{Version: "v1.54.0"},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(
				conda, conda,
				pkg.Package{Name: "installed", Type: pkg.PythonPkg, FoundBy: "python-installed-package-cataloger"},
				pkg.Package{Name: "wheel", Type: pkg.PythonPkg, FoundBy: "python-package-cataloger"},
				pkg.Package{Name: "libc", Type: pkg.DebPkg},
			),
			Unknowns: map[file.Coordinates][]string{
				{RealPath: "/bad.json"}: {"first error", "second error"},
				{RealPath: "/other"}:    {"unknown executable"},
			},
		},
	}
	got := resultForSBOM(bom, "report.cdx.json")
	want := Result{Path: "report.cdx.json", SyftVersion: "v1.54.0", Conda: 1, PythonInstalled: 1, Other: 2, Total: 4, Unknowns: 2}
	if got != want {
		t.Fatalf("result = %+v; want %+v", got, want)
	}
}

func TestWriteImageValidation(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteImage(ctx, nil, "unused", filepath.Join(root, "canceled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if _, err := WriteImage(context.Background(), nil, "unused", filepath.Join(root, "nil")); err == nil {
		t.Fatal("expected nil image error")
	}
	if _, err := WriteImage(context.Background(), &image.Image{}, "unused", filepath.Join(root, "identity")); err == nil {
		t.Fatal("expected missing identity error")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("validation created outputs: %v, %v", entries, err)
	}
}

func TestWriteImageRefusesExistingOutput(t *testing.T) {
	img := &image.Image{
		Metadata: image.Metadata{ManifestDigest: "sha256:" + strings.Repeat("a", 64), OS: "linux", Architecture: "amd64"},
		Layers:   []*image.Layer{{}}, // No squashed tree: scanning this image would fail.
	}
	filename, err := imageFilename(img)
	if err != nil {
		t.Fatal(err)
	}
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "dangling symlink"}[symlink], func(t *testing.T) {
			output := t.TempDir()
			destination := filepath.Join(output, filename)
			if symlink {
				err = os.Symlink("missing-target", destination)
			} else {
				err = os.WriteFile(destination, []byte("original"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := WriteImage(context.Background(), img, "unused", output); !errors.Is(err, os.ErrExist) {
				t.Fatalf("expected output collision before scan, got %v", err)
			}
			if symlink {
				target, err := os.Readlink(destination)
				if err != nil || target != "missing-target" {
					t.Fatalf("symlink changed: %q, %v", target, err)
				}
			} else {
				data, err := os.ReadFile(destination)
				if err != nil || string(data) != "original" {
					t.Fatalf("existing output changed: %q, %v", data, err)
				}
			}
		})
	}
}

func TestWriteImageRemovesOutputOnScanFailure(t *testing.T) {
	output := filepath.Join(t.TempDir(), "reports")
	img := &image.Image{
		Metadata: image.Metadata{ManifestDigest: "sha256:" + strings.Repeat("a", 64)},
		Layers:   []*image.Layer{{}},
	}
	if _, err := WriteImage(context.Background(), img, "unused", output); err == nil || !strings.Contains(err.Error(), "file resolver") {
		t.Fatalf("expected missing squashed tree scan error, got %v", err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed scan left outputs: %v, %v", entries, err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("output is not a directory: %v", info)
	}
	// Windows access permissions are ACL-based, not POSIX FileMode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("output directory is not private: %v, %v", info, err)
	}
}

func TestWriteImage(t *testing.T) {
	archive := testimage.Archive(t,
		[]testimage.Entry{
			{Name: "opt/conda/conda-meta/deleted.json", Data: `{"name":"deleted","version":"1","build":"0"}`},
			{Name: "opt/conda/conda-meta/current.json", Data: `{"name":"current","version":"1","build":"0"}`},
			{Name: "opt/conda/lib/python3.12/site-packages/demo-1.0.dist-info/METADATA", Data: "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"},
			{Name: "other/conda-meta/opaque.json", Data: `{"name":"opaque","version":"1","build":"0"}`},
		},
		[]testimage.Entry{
			{Name: "opt/conda/conda-meta/.wh.deleted.json"},
			{Name: "opt/conda/conda-meta/current.json", Data: `{"name":"current","version":"2","build":"0"}`},
			{Name: "other/conda-meta/.wh..wh..opq"},
			{Name: "other/conda-meta/replacement.json", Data: `{"name":"replacement","version":"1","build":"0"}`},
			{Name: "var/lib/dpkg/status", Data: "Package: system-demo\nStatus: install ok installed\nVersion: 1.2\nArchitecture: amd64\nDescription: demo system package\n\n"},
			{Name: "broken/conda-meta/malformed.json", Data: "{"},
		},
	)
	loaded, err := imageinput.Load(context.Background(), archive, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loaded.Close(); err != nil {
			t.Error(err)
		}
	})
	output := filepath.Join(t.TempDir(), "private", "reports")
	result, err := WriteImage(context.Background(), loaded.Image, archive, output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Conda != 2 || result.PythonInstalled != 1 || result.Other != 1 || result.Total != 4 || result.Unknowns != 1 {
		t.Fatalf("unexpected whole-image Syft observations: %+v", result)
	}
	if !strings.Contains(filepath.Base(result.Path), strings.TrimPrefix(loaded.Identity.ManifestDigest, "sha256:")) {
		t.Fatalf("filename omits full manifest identity: %q", result.Path)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Metadata struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
				BOMRef  string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	component := bom.Metadata.Component
	if component.Name != archive || component.Version != loaded.Identity.ManifestDigest || component.Type != "container" || component.BOMRef == "" {
		t.Fatalf("incorrect source metadata: %+v", component)
	}
	found := map[string]string{}
	for _, component := range bom.Components {
		if component.Type != "file" {
			found[component.Name] = component.Version
		}
	}
	if len(found) != 4 || found["current"] != "2" || found["replacement"] != "1" || found["demo"] != "1.0" || found["system-demo"] != "1.2" {
		t.Fatalf("unexpected squashed packages: %v", found)
	}
	for _, path := range []string{output, filepath.Dir(output), result.Path} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o700)
		if path == result.Path {
			want = 0o600
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != want {
			t.Fatalf("non-private output mode for %s: %o", path, info.Mode().Perm())
		}
	}
	reader, err := loaded.Image.OpenPathFromSquash("/opt/conda/conda-meta/current.json")
	if err != nil {
		t.Fatalf("writer cleaned up caller-owned image: %v", err)
	}
	contents, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !bytes.Contains(contents, []byte(`"version":"2"`)) {
		t.Fatalf("caller-owned image cannot be reused: %q, %v, %v", contents, err, closeErr)
	}
	second, err := WriteImage(context.Background(), loaded.Image, "registry.example/demo:changed", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(second.Path) != filepath.Base(result.Path) {
		t.Fatalf("mutable input affected filename: %q != %q", second.Path, result.Path)
	}
	if _, err := WriteImage(context.Background(), loaded.Image, "unused", output); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected overwrite refusal, got %v", err)
	}
	again, err := os.ReadFile(result.Path)
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("existing image SBOM changed: %v", err)
	}
}
