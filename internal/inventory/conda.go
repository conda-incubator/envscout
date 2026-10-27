package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // Syft's RPM cataloger requires the SQLite driver.

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/conda-incubator/envscout/internal/discovery"
)

// Result describes what Syft cataloged from an installed prefix or image.
// PythonInstalled counts Python installation metadata, not necessarily pip installs.
type Result struct {
	Path            string `json:"path"`
	PreExisting     bool   `json:"pre_existing,omitempty"` // Skipped output; counts and freshness were not inspected.
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

// errUnknownKind reports an environment whose Kind is neither KindConda nor KindVenv.
var errUnknownKind = errors.New("unknown environment kind")

// WriteEnvironment scans only env.Path and saves CycloneDX JSON, or reports a
// pre-existing regular output without reading, replacing or validating it.
// KindConda uses the default directory source. KindVenv confines the source to env.Path so that
// relative interpreter or library links cannot pull packages from outside the prefix.
// Any other Kind, including the empty string, is rejected before the source opens.
func WriteEnvironment(ctx context.Context, env discovery.Environment, outputDir string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	var (
		src source.Source
		err error
	)
	switch env.Kind {
	case discovery.KindConda:
		src, err = directorysource.NewFromPath(env.Path)
	case discovery.KindVenv:
		config := directorysource.Config{Path: env.Path, Base: env.Path}
		// Syft's Base does not confine drive-qualified Windows symlink targets.
		if os.PathSeparator == '\\' {
			config, err = virtualenvSourceConfig(ctx, env.Path)
			if err != nil {
				break
			}
		}
		src, err = directorysource.New(config)
	default:
		return Result{}, fmt.Errorf("environment %s: %w %q", env.Path, errUnknownKind, env.Kind)
	}
	if err != nil {
		return Result{}, fmt.Errorf("open environment %s: %w", env.Path, err)
	}
	result, writeErr := write(ctx, src, filepath.Join(outputDir, Filename(env)), env.Kind == discovery.KindConda)
	if err := src.Close(); err != nil {
		// Joined so a source close failure is reported without masking the write outcome.
		return result, errors.Join(writeErr, fmt.Errorf("close environment %s: %w", env.Path, err))
	}
	return result, writeErr
}

// write reserves destination exclusively, catalogs src, and encodes CycloneDX JSON into it.
// Any failure after reservation removes the partial file. The caller owns src.
func write(ctx context.Context, src source.Source, destination string, withConda bool) (result Result, err error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return Result{}, fmt.Errorf("create SBOM directory: %w", err)
	}
	// Reserve the destination before cataloging, including against concurrent writers.
	// O_EXCL refuses to follow an existing symlink, including a dangling one.
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		if info, statErr := os.Lstat(destination); statErr == nil && info.Mode().IsRegular() {
			return Result{Path: destination, PreExisting: true}, nil
		}
		return Result{}, fmt.Errorf("create SBOM %s: SBOM already exists: %w", destination, err)
	} else if err != nil {
		return Result{}, fmt.Errorf("create SBOM %s: %w", destination, err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(destination)
		}
	}()
	bom, err := catalog(ctx, src, withConda)
	if err != nil {
		return Result{}, fmt.Errorf("scan %s: %w", destination, err)
	}
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return Result{}, fmt.Errorf("configure CycloneDX output: %w", err)
	}
	// Encoding has no context API; check around it and remove output on cancellation.
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := encoder.Encode(file, *bom); err != nil {
		return Result{}, fmt.Errorf("encode SBOM %s: %w", destination, err)
	}
	if err := file.Close(); err != nil {
		return Result{}, fmt.Errorf("close SBOM %s: %w", destination, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	complete = true
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
