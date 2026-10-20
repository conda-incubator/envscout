package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

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
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create SBOM directory: %w", err)
	}
	destination := filepath.Join(outputDir, filename)
	// Reserve the destination before cataloging, including against concurrent writers.
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("create SBOM %s: %w", destination, err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(destination)
		}
	}()

	src := stereoscopesource.New(img, stereoscopesource.ImageConfig{Reference: input})
	cfg := syft.DefaultCreateSBOMConfig().WithParallelism(4)
	cfg.Search.Scope = source.SquashedScope
	// Syft v1.54 tags this installed-package cataloger for directories, not images.
	cfg.CatalogerSelection = cataloging.NewSelectionRequest().WithAdditions("conda-meta-cataloger")
	// Keep image cataloging offline and independent of host package caches/tooling.
	cfg.Packages.Golang.SearchRemoteLicenses = false
	cfg.Packages.Golang.SearchLocalModCacheLicenses = false
	cfg.Packages.Golang.SearchLocalVendorLicenses = false
	cfg.Packages.Golang.UsePackagesLib = false
	cfg.Packages.Python.SearchRemoteLicenses = false
	cfg.Packages.JavaScript.SearchRemoteLicenses = false
	cfg.Packages.JavaArchive.UseNetwork = false
	cfg.Packages.JavaArchive.UseMavenLocalRepository = false
	// These flags disable generic zip/tar wrappers, not traversal inside JARs.
	cfg.Packages.JavaArchive.IncludeIndexedArchives = false
	cfg.Packages.JavaArchive.IncludeUnindexedArchives = false
	bom, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return Result{}, fmt.Errorf("scan image %s: %w", input, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return Result{}, fmt.Errorf("configure CycloneDX output: %w", err)
	}
	if err := encoder.Encode(contextWriter{ctx: ctx, writer: file}, *bom); err != nil {
		return Result{}, fmt.Errorf("encode SBOM %s: %w", destination, err)
	}
	result := resultForSBOM(bom, destination)
	if err := file.Close(); err != nil {
		return Result{}, fmt.Errorf("close SBOM %s: %w", destination, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	complete = true
	return result, nil
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

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.writer.Write(p)
}
