package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

// ImageSource wraps a loaded image as a Syft source for the squashed filesystem. It borrows
// img: the caller owns img and must not pass the returned source to anything that closes it
// unless the caller also owns the image. Closing the source cleans up the image.
func ImageSource(img *image.Image, input string) source.Source {
	return stereoscopesource.New(img, stereoscopesource.ImageConfig{Reference: input})
}

// WriteImage catalogs the loaded image's squashed filesystem and writes CycloneDX JSON.
// The caller owns img; this function never closes its source or cleans up the image.
func WriteImage(ctx context.Context, img *image.Image, input string, outputDir string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if img == nil {
		return Result{}, fmt.Errorf("image is nil")
	}
	filename, err := imageFilename(img)
	if err != nil {
		return Result{}, err
	}
	return write(ctx, ImageSource(img, input), filepath.Join(outputDir, filename), true)
}

func imageFilename(img *image.Image) (string, error) {
	kind, digest := "manifest", img.Metadata.ManifestDigest
	if digest == "" {
		kind, digest = "config", img.Metadata.ID
	}
	value, ok := strings.CutPrefix(digest, "sha256:")
	decoded, err := hex.DecodeString(value)
	if !ok || err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("image %s digest is not a full sha256 digest: %q", kind, digest)
	}
	filename := fmt.Sprintf("image-%s-sha256-%s-%s-%s", kind, hex.EncodeToString(decoded),
		url.PathEscape(img.Metadata.OS), url.PathEscape(img.Metadata.Architecture))
	if img.Metadata.Variant != "" {
		filename += "-" + url.PathEscape(img.Metadata.Variant)
	}
	return filename + ".cdx.json", nil
}
