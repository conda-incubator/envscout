package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/conda"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Catalog runs offline Syft cataloging over src and returns the SBOM. It never closes src:
// callers that own the source must close it, and callers that borrow it (such as an image
// owned by the caller) must not. The conda-meta cataloger is added explicitly because Syft
// v1.54 tags it for directories only. Remote lookups and host caches are disabled.
func Catalog(ctx context.Context, src source.Source) (*sbom.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cataloger := &validatedCondaCataloger{Cataloger: conda.NewCondaMetaCataloger()}
	cfg := offlineConfig().WithCatalogers(pkgcataloging.NewAlwaysEnabledCatalogerReference(cataloger))
	bom, err := syft.CreateSBOM(ctx, src, cfg)
	err = errors.Join(err, ctx.Err())
	if err != nil {
		return bom, fmt.Errorf("catalog %s: %w", src.Describe().Name, err)
	}
	for _, p := range cataloger.invalid {
		addUnknowns(bom, p)
	}
	return bom, nil
}

// Validate conda before Syft's SBOM-wide compliance drops or stubs missing fields.
// Other ecosystems keep Syft's default compliance behavior; metadata is read once.
type validatedCondaCataloger struct {
	pkg.Cataloger
	invalid []pkg.Package
}

func (c *validatedCondaCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	packages, relationships, err := c.Cataloger.Catalog(ctx, resolver)
	valid := packages[:0]
	for _, p := range packages {
		if invalidCondaRecord(p) {
			c.invalid = append(c.invalid, p)
		} else {
			valid = append(valid, p)
		}
	}
	return valid, relationships, err
}

// addUnknowns records invalidCondaReason against every location of p.
func addUnknowns(bom *sbom.SBOM, p pkg.Package) {
	if bom.Artifacts.Unknowns == nil {
		bom.Artifacts.Unknowns = map[file.Coordinates][]string{}
	}
	for _, l := range p.Locations.ToSlice() {
		if !slices.Contains(bom.Artifacts.Unknowns[l.Coordinates], invalidCondaReason) {
			bom.Artifacts.Unknowns[l.Coordinates] = append(bom.Artifacts.Unknowns[l.Coordinates], invalidCondaReason)
		}
	}
}

// invalidCondaRecord reports whether p is a conda package whose metadata lacks a name or
// version. Syft's conda parser accepts such records, so inventory must reject them itself.
func invalidCondaRecord(p pkg.Package) bool {
	return p.Type == pkg.CondaPkg && (p.Name == "" || p.Version == "")
}

// invalidCondaReason is the unknown recorded for each location of a dropped conda record.
const invalidCondaReason = "invalid conda record: empty name or version"

// CondaRecords returns conda-meta package records from src without a full SBOM, so callers
// that only need Conda metadata skip the other catalogers. It never closes src. Records that
// Syft parsed from files with errors are returned with the error. Records with an empty name
// or version are dropped and reported in one validation error that names their locations.
// Result order follows Syft's completion order and is not deterministic; callers sort.
func CondaRecords(ctx context.Context, src source.Source, scope source.Scope) ([]pkg.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolver, err := src.FileResolver(scope)
	if err != nil {
		return nil, fmt.Errorf("resolve files for %s: %w", src.Describe().Name, err)
	}
	pkgs, _, err := conda.NewCondaMetaCataloger().Catalog(ctx, resolver)
	err = errors.Join(err, ctx.Err())
	valid := pkgs[:0]
	var invalid []string
	for _, p := range pkgs {
		if invalidCondaRecord(p) {
			invalid = append(invalid, fmt.Sprintf("%q/%q at %s", p.Name, p.Version, locationList(p)))
			continue
		}
		valid = append(valid, p)
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		err = errors.Join(err, fmt.Errorf("dropped %d conda record(s) with empty name or version: %v", len(invalid), invalid))
	}
	return valid, err
}

func locationList(p pkg.Package) string {
	var out []string
	for _, l := range p.Locations.ToSlice() {
		out = append(out, l.RealPath)
	}
	return fmt.Sprint(out)
}

// offlineConfig is the shared Syft configuration for directory and image inventories.
func offlineConfig() *syft.CreateSBOMConfig {
	cfg := syft.DefaultCreateSBOMConfig().WithParallelism(4)
	cfg.Search.Scope = source.SquashedScope
	cfg.CatalogerSelection = cataloging.NewSelectionRequest().WithRemovals("conda-meta-cataloger")
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
	return cfg
}
