package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // Syft's RPM cataloger requires the SQLite driver.

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
)

// Result describes what Syft cataloged from an installed prefix or image.
// PythonInstalled counts Python installation metadata, not necessarily pip installs.
type Result struct {
	Path            string `json:"path"`
	SyftVersion     string `json:"syft_version"`
	Conda           int    `json:"conda"`
	PythonInstalled int    `json:"python_installed"`
	Other           int    `json:"other"`
	Total           int    `json:"total"`    // Unique packages, not CycloneDX components.
	Unknowns        int    `json:"unknowns"` // File coordinates with unknowns, not individual diagnostic messages.
}

// Filename identifies a prefix by a readable folder name and its absolute path.
func Filename(env discovery.Environment) string {
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, env.Name)
	name = strings.Trim(name, "-_")
	if name == "" {
		name = "env"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	hash := sha256.Sum256([]byte(env.Path))
	return fmt.Sprintf("%s-%s.cdx.json", name, hex.EncodeToString(hash[:8]))
}

// WriteConda scans only env.Path and saves a CycloneDX JSON document without replacing any prior output.
func WriteConda(ctx context.Context, env discovery.Environment, outputDir string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create SBOM directory: %w", err)
	}
	destination := filepath.Join(outputDir, Filename(env))
	if _, err := os.Lstat(destination); err == nil {
		return Result{}, fmt.Errorf("SBOM already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return Result{}, fmt.Errorf("check SBOM destination %s: %w", destination, err)
	}
	src, err := directorysource.NewFromPath(env.Path)
	if err != nil {
		return Result{}, fmt.Errorf("open environment %s: %w", env.Path, err)
	}
	defer func() { _ = src.Close() }()
	bom, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig().WithParallelism(4))
	if err != nil {
		return Result{}, fmt.Errorf("scan environment %s: %w", env.Path, err)
	}
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return Result{}, fmt.Errorf("configure CycloneDX output: %w", err)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("create SBOM %s: %w", destination, err)
	}
	if err := encoder.Encode(file, *bom); err != nil {
		_ = file.Close()
		_ = os.Remove(destination)
		return Result{}, fmt.Errorf("encode SBOM %s: %w", destination, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(destination)
		return Result{}, fmt.Errorf("close SBOM %s: %w", destination, err)
	}
	return resultForSBOM(bom, destination), nil
}

func resultForSBOM(bom *sbom.SBOM, destination string) Result {
	result := Result{
		Path:        destination,
		SyftVersion: bom.Descriptor.Version,
		Total:       bom.Artifacts.Packages.PackageCount(),
		Unknowns:    len(bom.Artifacts.Unknowns),
	}
	for p := range bom.Artifacts.Packages.Enumerate() {
		switch {
		case p.Type == pkg.CondaPkg:
			result.Conda++
		case p.Type == pkg.PythonPkg && p.FoundBy == "python-installed-package-cataloger":
			result.PythonInstalled++
		default:
			result.Other++
		}
	}
	return result
}
