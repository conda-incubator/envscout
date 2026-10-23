// Package imageinput opens an OCI image archive for one explicit platform
// through stereoscope. It exposes the selected image, whose canonical metadata
// (config, raw manifest, layer digests and sizes) lives on Image, plus a
// user-facing Identity projection.
package imageinput

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/image/oci"
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

// Loaded owns the one image used for discovery and inventory. Image.Metadata is
// the canonical source for config, raw manifest, and layer digests and sizes.
type Loaded struct {
	Image    *image.Image
	Identity Identity
	gen      *file.TempDirGenerator
}

// Close releases the staged image and its temp directories. It is idempotent
// and safe on a nil receiver.
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

// Load opens the OCI archive at input for platform using DefaultLimits.
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
	// RawManifest is best-effort in the provider, so it is the one canonical field
	// that can be absent; the layer count is checked against the config diff IDs.
	if len(img.Metadata.RawManifest) == 0 || len(img.Metadata.Config.RootFS.DiffIDs) != len(img.Layers) {
		return nil, errors.Join(fmt.Errorf("image metadata incomplete: manifest or layer diff IDs unavailable"), img.Cleanup(), gen.Cleanup())
	}
	return &Loaded{Image: img, Identity: identityFromImage(img, abs), gen: gen}, nil
}

// identityFromImage projects the provider-populated metadata into the
// user-facing Identity. The OCI provider always sets ManifestDigest and ID
// (the ggcr config name, sha256-prefixed), and Read fills OS/Architecture/Variant
// from the same config that the provider platform check validated.
func identityFromImage(img *image.Image, abs string) Identity {
	return Identity{
		Source:         "oci-archive",
		Input:          abs,
		ManifestDigest: img.Metadata.ManifestDigest,
		ConfigDigest:   img.Metadata.ID,
		OS:             img.Metadata.OS,
		Architecture:   img.Metadata.Architecture,
		Variant:        img.Metadata.Variant,
	}
}
