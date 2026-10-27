package inventory

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/imageinput"
	"github.com/conda-incubator/envscout/internal/testimage"
)

// TestOfflineConfig pins every remote lookup, host cache, and archive network flag that the
// shared Syft configuration must disable for both directory and image inventories.
func TestOfflineConfig(t *testing.T) {
	cfg := offlineConfig()
	disabled := map[string]bool{
		"golang remote licenses":           cfg.Packages.Golang.SearchRemoteLicenses,
		"golang mod cache licenses":        cfg.Packages.Golang.SearchLocalModCacheLicenses,
		"golang vendor licenses":           cfg.Packages.Golang.SearchLocalVendorLicenses,
		"golang packages lib":              cfg.Packages.Golang.UsePackagesLib,
		"python remote licenses":           cfg.Packages.Python.SearchRemoteLicenses,
		"javascript remote licenses":       cfg.Packages.JavaScript.SearchRemoteLicenses,
		"java archive network":             cfg.Packages.JavaArchive.UseNetwork,
		"java maven local repository":      cfg.Packages.JavaArchive.UseMavenLocalRepository,
		"java indexed archive traversal":   cfg.Packages.JavaArchive.IncludeIndexedArchives,
		"java unindexed archive traversal": cfg.Packages.JavaArchive.IncludeUnindexedArchives,
	}
	for name, enabled := range disabled {
		if enabled {
			t.Errorf("%s is enabled, want disabled", name)
		}
	}
	if cfg.Search.Scope != source.SquashedScope {
		t.Errorf("search scope = %v, want squashed", cfg.Search.Scope)
	}
	want := cataloging.NewSelectionRequest().WithRemovals("conda-meta-cataloger")
	if len(cfg.CatalogerSelection.RemoveNamesOrTags) != len(want.RemoveNamesOrTags) || cfg.CatalogerSelection.RemoveNamesOrTags[0] != "conda-meta-cataloger" {
		t.Errorf("cataloger removals = %v, want conda-meta-cataloger", cfg.CatalogerSelection.RemoveNamesOrTags)
	}
	if cfg.Compliance != cataloging.DefaultComplianceConfig() {
		t.Fatalf("non-conda compliance must use Syft defaults: %+v", cfg.Compliance)
	}
}

func TestCatalogKeepsPythonComplianceDefaults(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, "lib", "python3.12", "site-packages", "demo.dist-info")
	if err := os.MkdirAll(metadata, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadata, "METADATA"), []byte("Metadata-Version: 2.1\nName: demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	bom, err := Catalog(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	for p := range bom.Artifacts.Packages.Enumerate(pkg.PythonPkg) {
		if p.Name == "demo" && p.Version == cataloging.UnknownStubValue {
			return
		}
	}
	t.Fatal("missing Python version no longer receives Syft's UNKNOWN stub")
}

// TestOfflineConfigMakesNoRemoteRequests catalogs a Go module and Python metadata while an
// httptest server is the only reachable endpoint; any remote request fails the test.
func TestOfflineConfigMakesNoRemoteRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "remote lookups are forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("GOPROXY", server.URL)
	t.Setenv("GOFLAGS", "-mod=mod")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(root, "lib", "python3.12", "site-packages", "demo-1.0.dist-info")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "METADATA"), []byte("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nLicense: MIT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	bom, err := Catalog(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if bom == nil || requests.Load() != 0 {
		t.Fatalf("catalog made %d remote request(s)", requests.Load())
	}
}

func TestCatalogCanceledBeforeScan(t *testing.T) {
	src, err := directorysource.NewFromPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Catalog(ctx, src); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func condaFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	meta := filepath.Join(root, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(meta, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCondaRecordsReturnsCondaOnly(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"python-3.12-0.json": canonicalRecordJSON("python", "3.12"),
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(records), records)
	}
	p := records[0]
	if p.Record.Name != "python" || p.Record.Version != "3.12" || p.Record.Build != "0" {
		t.Fatalf("unexpected record: %+v", p)
	}
	if !strings.HasSuffix(p.Path, "conda-meta/python-3.12-0.json") || p.Record.SourcePath != p.Path {
		t.Fatalf("record lost its location: %+v", p)
	}
	// Borrowed source must still resolve after CondaRecords returns.
	if _, err := src.FileResolver(source.SquashedScope); err != nil {
		t.Fatalf("CondaRecords closed the borrowed source: %v", err)
	}
}

func TestCondaRecordsMalformedJSONReturnsPartialWithError(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"good-1.0-0.json": canonicalRecordJSON("good", "1.0"),
		"bad-1.0-0.json":  `{`,
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err == nil || !strings.Contains(err.Error(), "bad-1.0-0.json") {
		t.Fatalf("expected malformed JSON error naming the file, got %v", err)
	}
	if len(records) != 1 || records[0].Record.Name != "good" {
		t.Fatalf("partial records = %+v, want only good", records)
	}
}

func TestCondaRecordsRejectsEmptyNameOrVersion(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"noname-1.0-0.json": strings.Replace(canonicalRecordJSON("noname", "1.0"), `"name":"noname"`, `"name":""`, 1),
		"nover-0-0.json":    strings.Replace(canonicalRecordJSON("nover", "1.0"), `"version":"1.0"`, `"version":""`, 1),
		"ok-2.0-0.json":     canonicalRecordJSON("ok", "2.0"),
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err == nil {
		t.Fatal("expected validation errors for two invalid records")
	}
	for _, name := range []string{"noname-1.0-0.json", "nover-0-0.json"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("validation error omits location %s: %v", name, err)
		}
	}
	if len(records) != 1 || records[0].Record.Name != "ok" {
		t.Fatalf("records = %+v, want only ok", records)
	}
}

func TestCondaRecordsCanceledReturnsNoRecords(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"python-3.12-0.json": `{"name":"python","version":"3.12","build":"0"}`,
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	records, err := CondaRecords(ctx, src, source.SquashedScope)
	if !errors.Is(err, context.Canceled) || records != nil {
		t.Fatalf("canceled call = %+v, %v; want nil records and context.Canceled", records, err)
	}
}

func TestWriteEnvironmentInvalidRecordIsIncomplete(t *testing.T) {
	prefix := condaFixtureDir(t, `{"name":"","version":"1","build":"0"}`)
	env := discovery.Environment{Name: "sample", Path: prefix, Kind: discovery.KindConda}
	result, err := WriteEnvironment(context.Background(), env, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.Conda != 0 || result.Unknowns != 1 {
		t.Fatalf("invalid record must not count as conda and must mark one unknown: %+v", result)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"name": ""`) {
		t.Fatalf("invalid conda component leaked into SBOM: %s", data)
	}
}

func TestWriteImageInvalidRecordIsIncomplete(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "opt/conda/conda-meta/blank.json", Data: `{"name":"blank","version":"","build":"0"}`},
	}, nil)
	loaded, err := imageinput.Load(context.Background(), archive, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	result, err := WriteImage(context.Background(), loaded.Image, archive, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.Conda != 0 || result.Unknowns != 1 {
		t.Fatalf("invalid image record must not count as conda and must mark one unknown: %+v", result)
	}
}

func TestCatalogDropsInvalidRecordAndKeepsSBOM(t *testing.T) {
	prefix := condaFixtureDir(t, `{"name":"","version":"1","build":"0"}`)
	src, err := directorysource.NewFromPath(prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	bom, err := Catalog(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if bom == nil || bom.Artifacts.Packages.PackageCount() != 0 || len(bom.Artifacts.Unknowns) != 1 {
		t.Fatalf("unexpected SBOM after invalid record: packages=%d unknowns=%v", bom.Artifacts.Packages.PackageCount(), bom.Artifacts.Unknowns)
	}
	for _, reasons := range bom.Artifacts.Unknowns {
		if len(reasons) != 1 || reasons[0] != invalidCondaReason {
			t.Fatalf("unknown reason = %v", reasons)
		}
	}
}

func condaFixtureDir(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "conda-meta"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "conda-meta", "record-0-0.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
