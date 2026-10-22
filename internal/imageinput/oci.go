// Package imageinput opens an OCI image archive for one explicit platform
// through stereoscope and exposes the selected image, its manifest, config,
// and identity.
package imageinput

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/image/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Limits bound the accepted archive size. They do not constitute a process
// memory or wall-clock quota.
type Limits struct {
	ArchiveBytes int64
}

func DefaultLimits() Limits {
	return Limits{ArchiveBytes: 1 << 30}
}

type Identity struct {
	Source         string `json:"source"`
	Input          string `json:"input"`
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
	Variant        string `json:"variant,omitempty"`
}

// Loaded owns the one image used for discovery and inventory.
type Loaded struct {
	Image    *image.Image
	Identity Identity
	Manifest *v1.Manifest
	Config   *v1.ConfigFile
	gen      *file.TempDirGenerator
}

func (l *Loaded) Close() error {
	if l == nil {
		return nil
	}
	var err error
	if l.Image != nil {
		err = l.Image.Cleanup()
		l.Image = nil
	}
	if l.gen != nil {
		err = errors.Join(err, l.gen.Cleanup())
		l.gen = nil
	}
	return err
}

func Load(ctx context.Context, input, platform string) (*Loaded, error) {
	return LoadWithLimits(ctx, input, platform, DefaultLimits())
}

// LoadWithLimits checks the archive size bound, then lets stereoscope untar
// the OCI archive, select the image for the platform, and index it once.
func LoadWithLimits(ctx context.Context, input, platform string, limits Limits) (*Loaded, error) {
	if limits.ArchiveBytes <= 0 {
		return nil, fmt.Errorf("image limits must be positive")
	}
	parts := strings.Split(platform, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("OCI images require --platform OS/ARCH[/VARIANT]")
	}
	p, err := image.NewPlatform(platform)
	if err != nil || p == nil || p.OS != parts[0] || p.Architecture == "" {
		return nil, fmt.Errorf("invalid image platform %q", platform)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("open OCI archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > limits.ArchiveBytes {
		return nil, fmt.Errorf("OCI archive must be a regular file of at most %d bytes", limits.ArchiveBytes)
	}
	gen := file.NewTempDirGenerator("envscout-image")
	img, err := oci.NewArchiveProviderWithPlatform(gen, abs, p).Provide(ctx)
	if err != nil {
		if img != nil {
			err = errors.Join(err, img.Cleanup())
		}
		return nil, errors.Join(err, gen.Cleanup())
	}
	if img == nil {
		return nil, errors.Join(fmt.Errorf("image provider returned no image"), gen.Cleanup())
	}
	loaded, err := describe(img, abs, gen)
	if err != nil {
		return nil, errors.Join(err, img.Cleanup(), gen.Cleanup())
	}
	return loaded, nil
}

// describe derives the manifest, config copy, and identity evidence consumers
// require from the indexed image.
func describe(img *image.Image, abs string, gen *file.TempDirGenerator) (*Loaded, error) {
	var manifest v1.Manifest
	if err := json.Unmarshal(img.Metadata.RawManifest, &manifest); err != nil {
		return nil, fmt.Errorf("image manifest unavailable: %w", err)
	}
	if len(manifest.Layers) != len(img.Layers) {
		return nil, fmt.Errorf("image manifest lists %d layers but %d were indexed", len(manifest.Layers), len(img.Layers))
	}
	cfg := img.Metadata.Config
	configDigest := img.Metadata.ID
	if !strings.HasPrefix(configDigest, "sha256:") {
		configDigest = manifest.Config.Digest.String()
	}
	identity := Identity{
		Source:         "oci-archive",
		Input:          abs,
		ManifestDigest: img.Metadata.ManifestDigest,
		ConfigDigest:   configDigest,
		OS:             img.Metadata.OS,
		Architecture:   img.Metadata.Architecture,
		Variant:        img.Metadata.Variant,
	}
	if identity.OS == "" {
		identity.OS = cfg.OS
	}
	if identity.Architecture == "" {
		identity.Architecture = cfg.Architecture
	}
	if identity.Variant == "" {
		identity.Variant = cfg.Variant
	}
	if !validDigest(identity.ManifestDigest) || !validDigest(identity.ConfigDigest) {
		return nil, fmt.Errorf("image identity digests are unavailable or malformed")
	}
	return &Loaded{Image: img, Manifest: &manifest, Config: &cfg, Identity: identity, gen: gen}, nil
}

func validDigest(digest string) bool {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
