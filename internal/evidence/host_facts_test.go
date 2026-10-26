package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
)

func hostWrite(t *testing.T, name, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostPythonOwnershipOmissionIsUnknown(t *testing.T) {
	prefix := hostPrefix(t)
	data := strings.Replace(hostRecordJSON("demo", ""), `,"files":[]`, "", 1)
	writeMeta(t, prefix, "pkg.json", data)
	hostWrite(t, filepath.Join(prefix, "lib/python3.12/site-packages/demo-1.dist-info/METADATA"), "Name: demo\nVersion: 1\n")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records", "python-distributions"}})
	if err != nil || len(snapshot.Targets[0].Python) != 1 || snapshot.Targets[0].Coverage["python-distributions"] != Partial || snapshot.Targets[0].Coverage["conda-records"] != Complete {
		t.Fatalf("missing file ownership treated as proven unowned: %+v %v", snapshot, err)
	}
}

func TestHostOversizedPythonMetadataIsUnknown(t *testing.T) {
	prefix := hostPrefix(t)
	hostWrite(t, filepath.Join(prefix, "lib/python3.12/site-packages/demo-1.dist-info/METADATA"), "Name: demo\nVersion: 1\n"+strings.Repeat("x", hostMetadataLimit))
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || snapshot.Targets[0].Coverage["python-distributions"] != Partial || len(snapshot.Targets[0].Python) != 0 {
		t.Fatalf("oversized Python metadata accepted: %+v %v", snapshot, err)
	}
}

func TestHostPythonGlobLimitCannotBecomeCompleteEmptyCatalog(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	r := &hostFileResolver{ctx: context.Background(), root: root, base: root.Name(), files: map[string]os.FileInfo{}}
	info := &stereofile.ManualInfo{ModeValue: 0o644}
	for i := 0; i <= hostEntryLimit; i++ {
		name := fmt.Sprintf("lib/python3.12/site-packages/pkg%d.dist-info/METADATA", i)
		r.files[name] = info
		r.paths = append(r.paths, name)
	}
	_, _, catalogErr := python.NewInstalledPackageCataloger().Catalog(context.Background(), r)
	if catalogErr == nil && r.issue == nil {
		t.Fatal("Syft swallowed bounded glob failure without retained resolver issue")
	}
}

func TestHostNoPrefixesCompletesSelectedCapabilities(t *testing.T) {
	caps := []string{"prefixes", "conda-records", "python-distributions", "host-cache", "installed-lock", "project-association"}
	snapshot, err := CollectHost(context.Background(), []string{t.TempDir()}, Request{Capabilities: caps})
	if err != nil || len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes) != 0 {
		t.Fatalf("non-conda root = %+v %v", snapshot, err)
	}
	for _, capability := range caps {
		if snapshot.Targets[0].Coverage[capability] != Complete {
			t.Fatalf("no subjects marked unknown for %s: %+v", capability, snapshot)
		}
	}
}

func TestHostCacheRejectsLinkedAndInvalidMarkers(t *testing.T) {
	prefix := hostPrefix(t)
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(filepath.Join(cache, "demo-1-0"))
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", `,"package_tarball_full_path":`+string(encoded)))
	hostWrite(t, filepath.Join(cache, "broken/info/index.json"), `{"name":"broken","version":"1"}`)
	out := filepath.Join(t.TempDir(), "outside-1-0.conda")
	hostWrite(t, out, "outside")
	if err := os.Symlink(out, filepath.Join(cache, "outside-1-0.conda")); err != nil {
		t.Skip(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || snapshot.Targets[0].Coverage["host-cache"] != Partial || len(snapshot.Targets[0].Archives)+len(snapshot.Targets[0].Extracted) != 0 {
		t.Fatalf("invalid/linked cache accepted: %+v %v", snapshot, err)
	}
}

func TestHostCacheAllowsLinkedParentButRejectsLinkedLeaf(t *testing.T) {
	parent := t.TempDir()
	cache := filepath.Join(parent, "real", "pkgs")
	hostWrite(t, filepath.Join(cache, "demo-1-0.conda"), "archive")
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(filepath.Join(parent, "real"), alias); err != nil {
		t.Skip(err)
	}
	prefix := hostPrefix(t)
	encoded, _ := json.Marshal(filepath.Join(alias, "pkgs", "demo-1-0.conda"))
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", `,"package_tarball_full_path":`+string(encoded)))
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || snapshot.Targets[0].Coverage["host-cache"] != Complete || len(snapshot.Targets[0].Archives) != 1 {
		t.Fatalf("an ordinary cache directory under an aliased parent is readable: %+v %v", snapshot, err)
	}
	leaf := filepath.Join(parent, "linked-pkgs")
	if err := os.Symlink(cache, leaf); err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(filepath.Join(leaf, "demo-1-0.conda"))
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", `,"package_tarball_full_path":`+string(encoded)))
	snapshot, err = CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || snapshot.Targets[0].Coverage["host-cache"] != Partial || len(snapshot.Targets[0].Archives) != 0 {
		t.Fatalf("a linked cache root is still not followed: %+v %v", snapshot, err)
	}
}

func TestHostCanonicalFactsDoNotBorrowDiscoveryCoverage(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	writeMeta(t, good, "conda.json", hostRecordJSON("conda", `,"requested_spec":"conda"`))
	writeMeta(t, filepath.Join(root, "bad"), "bad.json", `{"name":"broken"}`)
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"prefixes", "conda-records"}})
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("collection = %+v, %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	prefix := target.Prefixes[0]
	if target.Coverage["prefixes"] != Partial || target.Coverage["conda-records"] != Complete || prefix.RecordCoverage != Complete || !prefix.Tooling {
		t.Fatalf("unrelated discovery failure contaminated local facts: %+v", target)
	}
	if len(prefix.Records) != 1 || prefix.Records[0].Record.Name != "conda" || prefix.Records[0].Record.RequestedSpec != "conda" || prefix.Records[0].Path != filepath.Join(good, "conda-meta/conda.json") || prefix.Records[0].Record.SourcePath != prefix.Records[0].Path {
		t.Fatalf("canonical records discarded: %+v", prefix)
	}
}

func TestHostRecordSymlinkIsUnknownNotCompleteAbsence(t *testing.T) {
	prefix := hostPrefix(t)
	out := filepath.Join(t.TempDir(), "outside.json")
	hostWrite(t, out, hostRecordJSON("outside", ""))
	if err := os.Symlink(out, filepath.Join(prefix, "conda-meta/linked.json")); err != nil {
		t.Skip(err)
	}
	project := t.TempDir()
	hostWrite(t, filepath.Join(project, "pixi.lock"), hostPixiLock)
	hostPixiMarker(t, prefix, project, "linux-64")
	hostWrite(t, filepath.Join(prefix, "lib/python3.12/site-packages/outside-1.dist-info/METADATA"), "Name: outside\nVersion: 1\n")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records", "installed-lock"}})
	if err != nil || len(snapshot.Targets[0].Prefixes[0].Records) != 1 || snapshot.Targets[0].Prefixes[0].RecordCoverage != Partial || snapshot.Targets[0].Coverage["conda-records"] != Partial {
		t.Fatalf("linked record treated as known absence: %+v %v", snapshot, err)
	}
	if snapshot.Targets[0].Lock == nil || snapshot.Targets[0].Lock.Report != nil || snapshot.Targets[0].Coverage["installed-lock"] != Partial {
		t.Fatalf("skipped linked record used for a complete lock comparison: %+v", snapshot)
	}
}

func TestHostMalformedPythonMetadataIsUnknown(t *testing.T) {
	prefix := hostPrefix(t)
	hostWrite(t, filepath.Join(prefix, "lib/python3.12/site-packages/demo-1.dist-info/METADATA"), "Metadata-Version: 2.1\nVersion: 1\n")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || snapshot.Targets[0].Coverage["python-distributions"] != Partial || len(snapshot.Targets[0].Python) != 0 {
		t.Fatalf("malformed Python metadata treated as empty catalog: %+v %v", snapshot, err)
	}
}

func TestHostLargeCanonicalRecordKeepsFileOwnership(t *testing.T) {
	prefix := hostPrefix(t)
	files := make([]string, 25000)
	for i := range files {
		files[i] = fmt.Sprintf("lib/large/installed/payload/%08d/file-name-with-long-path.py", i)
	}
	encoded, _ := json.Marshal(files)
	data := hostRecordJSON("demo", `,"files":`+string(encoded))
	if len(data) <= hostMetadataLimit {
		t.Fatal("test fixture did not exceed small metadata bound")
	}
	writeMeta(t, prefix, "pkg.json", data)
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records"}})
	if err != nil || len(snapshot.Targets[0].Prefixes) != 1 || snapshot.Targets[0].Prefixes[0].RecordCoverage != Complete || len(snapshot.Targets[0].Prefixes[0].Records[0].Record.Files) != len(files) {
		t.Fatalf("large canonical ownership record rejected: %+v %v", snapshot, err)
	}
}

func TestHostPythonOwnershipUsesMetadataPathsNotNames(t *testing.T) {
	prefix := hostPrefix(t)
	owned := "lib/python3.12/site-packages/BeautifulSoup4-1.dist-info/METADATA"
	paths := "lib/python3.12/site-packages/mapped-1.egg-info/PKG-INFO"
	writeMeta(t, prefix, "bs.json", hostRecordJSON("beautifulsoup4-conda", `,"files":["`+owned+`"]`))
	writeMeta(t, prefix, "mapped.json", hostRecordJSON("different-conda-name", `,"paths_data":{"paths_version":1,"paths":[{"_path":"`+paths+`","path_type":"hardlink"}]}`))
	hostWrite(t, filepath.Join(prefix, filepath.FromSlash(owned)), "Metadata-Version: 2.1\nName: BeautifulSoup4\nVersion: 1\n")
	hostWrite(t, filepath.Join(prefix, filepath.FromSlash(paths)), "Metadata-Version: 2.1\nName: mapped\nVersion: 1\n")
	hostWrite(t, filepath.Join(prefix, "lib/python3.12/site-packages/demo-2.dist-info/METADATA"), "Metadata-Version: 2.1\nName: demo\nVersion: 2\n")
	hostWrite(t, filepath.Join(prefix, "requirements.txt"), "not-installed==7\n")
	hostWrite(t, filepath.Join(prefix, "package.json"), `{"name":"not-python","version":"1"}`)
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records", "python-distributions"}})
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("collection = %+v, %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	if target.Coverage["python-distributions"] != Complete || len(target.Python) != 3 {
		t.Fatalf("Python-only installed catalog = %+v", target)
	}
	want := map[string]string{"beautifulsoup4": "beautifulsoup4-conda", "mapped": "different-conda-name", "demo": ""}
	for _, dist := range target.Python {
		owner, ok := want[dist.Name]
		if !ok || dist.OwnedBy != owner || dist.Path == "" {
			t.Fatalf("distribution ownership = %+v", dist)
		}
	}
}

func TestHostPythonDoesNotFollowMetadataSymlink(t *testing.T) {
	prefix := hostPrefix(t)
	out := filepath.Join(t.TempDir(), "outside.dist-info")
	hostWrite(t, filepath.Join(out, "METADATA"), "Name: outside\nVersion: 1\n")
	inside := filepath.Join(prefix, "lib/python3.12/site-packages")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(inside, "outside.dist-info")); err != nil {
		t.Skip(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || len(snapshot.Targets[0].Python) != 0 || snapshot.Targets[0].Coverage["python-distributions"] != Partial {
		t.Fatalf("linked Python metadata accepted: %+v %v", snapshot, err)
	}
}

func TestHostPythonOnlySelectedPrefixInstallationRoots(t *testing.T) {
	prefix := hostPrefix(t)
	for _, relative := range []string{
		"lib/python3.12/site-packages/installed-1.dist-info/METADATA",
		"conda-bld/project/work/tests/fixture-1.dist-info/METADATA",
		"tools/venv/lib/python3.12/site-packages/nested-1.dist-info/METADATA",
		"src/tests/site-packages/fixture-1.egg-info/PKG-INFO",
	} {
		hostWrite(t, filepath.Join(prefix, relative), "Name: demo\nVersion: 1\n")
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || snapshot.Targets[0].Coverage["python-distributions"] != Complete || len(snapshot.Targets[0].Python) != 1 || !strings.Contains(snapshot.Targets[0].Python[0].Path, "installed-1.dist-info") {
		t.Fatalf("build fixtures/unrelated venvs treated as installed: %+v %v", snapshot, err)
	}
}

func TestHostPythonWindowsInstallationAndLinkedInstallationRoot(t *testing.T) {
	prefix := hostPrefix(t)
	hostWrite(t, filepath.Join(prefix, "Lib/site-packages/windows-1.dist-info/METADATA"), "Name: windows\nVersion: 1\n")
	out := t.TempDir()
	hostWrite(t, filepath.Join(out, "external-1.dist-info/METADATA"), "Name: external\nVersion: 1\n")
	if err := os.MkdirAll(filepath.Join(prefix, "lib/python3.12"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(prefix, "lib/python3.12/site-packages")); err != nil {
		t.Skip(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || snapshot.Targets[0].Coverage["python-distributions"] != Partial || len(snapshot.Targets[0].Python) != 1 || snapshot.Targets[0].Python[0].Name != "windows" {
		t.Fatalf("Windows or linked installation facts = %+v %v", snapshot, err)
	}
}

func TestHostCacheUsesOnlyRecordRootsAndCanonicalMarkers(t *testing.T) {
	prefix := hostPrefix(t)
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	packageDir := filepath.Join(cache, "demo-1-0")
	encoded, _ := json.Marshal(packageDir)
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", `,"extracted_package_dir":`+string(encoded)))
	hostWrite(t, filepath.Join(packageDir, "info/index.json"), `{"name":"demo","version":"1","build":"0","build_number":0,"subdir":"linux-64"}`)
	hostWrite(t, filepath.Join(packageDir, "lib/payload"), "payload")
	hostWrite(t, filepath.Join(cache, "demo-1-0.conda"), "archive")
	hostWrite(t, filepath.Join(cache, "renamed.conda"), "not a package archive filename")
	hostWrite(t, filepath.Join(prefix, "pkgs/unreferenced-1-0.conda"), "unreferenced")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("collection = %+v %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	if target.Coverage["host-cache"] != Complete || len(target.Archives) != 1 || len(target.Extracted) != 1 || target.Archives[0].Bytes != 7 || target.Extracted[0].Bytes != 0 {
		t.Fatalf("cache facts = %+v", target)
	}
}

func TestHostRecordPathsAreQualifiedToPrefix(t *testing.T) {
	prefix := hostPrefix(t)
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records"}})
	if err != nil || len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes[0].Records) != 1 {
		t.Fatalf("collection = %+v %v", snapshot, err)
	}
	record := snapshot.Targets[0].Prefixes[0].Records[0]
	want := filepath.Join(prefix, "conda-meta", "pkg.json")
	if record.Path != want || record.Record.SourcePath != want {
		t.Fatalf("virtual record path leaked: Path=%q SourcePath=%q want %q", record.Path, record.Record.SourcePath, want)
	}
}

func TestHostCrossRootArtifactCapIsGlobal(t *testing.T) {
	prefix := hostPrefix(t)
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Two record roots, each holding just under the per-root bound, together
	// exceed the shared artifact cap. The cap must hold across roots.
	for i := 0; i < 2; i++ {
		root := filepath.Join(cache, fmt.Sprintf("root%d", i))
		for j := 0; j < hostEntryLimit*3/4; j++ {
			hostWrite(t, filepath.Join(root, fmt.Sprintf("a%05d-1-0.conda", j)), "x")
		}
		writeMeta(t, prefix, fmt.Sprintf("r%d.json", i), hostRecordJSON(fmt.Sprintf("r%d", i), fmt.Sprintf(`,"package_tarball_full_path":%q`, filepath.Join(root, "x-1-0.conda"))))
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil {
		t.Fatal(err)
	}
	target := snapshot.Targets[0]
	if got := len(target.Archives) + len(target.Extracted); got > hostEntryLimit || target.Coverage["host-cache"] != Partial {
		t.Fatalf("cross-root artifacts = %d (cap %d), coverage %q", got, hostEntryLimit, target.Coverage["host-cache"])
	}
}

// A cache root reached through a benign parent alias (macOS /var -> /private/var
// style) must be read as a real leaf directory, not rejected for its parent alias.
func TestHostCacheRootThroughBenignParentAliasIsComplete(t *testing.T) {
	real := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skip(err)
	}
	prefix := hostPrefix(t)
	cacheDir := filepath.Join(alias, "pkgs")
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", fmt.Sprintf(`,"package_tarball_full_path":%q`, filepath.Join(cacheDir, "demo-1-0.conda"))))
	hostWrite(t, filepath.Join(real, "pkgs", "demo-1-0.conda"), "archive")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil {
		t.Fatal(err)
	}
	target := snapshot.Targets[0]
	if target.Coverage["host-cache"] != Complete || len(target.Archives) != 1 {
		t.Fatalf("benign parent alias made cache Partial or dropped artifact: coverage=%q archives=%+v issues=%+v", target.Coverage["host-cache"], target.Archives, target.Issues)
	}
}

// A symlinked leaf cache directory must not be followed.
func TestHostCacheLeafSymlinkIsPartialAndNotFollowed(t *testing.T) {
	outside := t.TempDir()
	hostWrite(t, filepath.Join(outside, "demo-1-0.conda"), "archive")
	prefix := hostPrefix(t)
	leaf := filepath.Join(t.TempDir(), "pkgs")
	if err := os.Symlink(outside, leaf); err != nil {
		t.Skip(err)
	}
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", fmt.Sprintf(`,"package_tarball_full_path":%q`, filepath.Join(leaf, "demo-1-0.conda"))))
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil {
		t.Fatal(err)
	}
	target := snapshot.Targets[0]
	if target.Coverage["host-cache"] != Partial || len(target.Archives) != 0 {
		t.Fatalf("symlinked leaf cache was followed: coverage=%q archives=%+v", target.Coverage["host-cache"], target.Archives)
	}
}

// Reviewer reproduction: the recorded cache root spells its parent through a
// benign alias, so the resolved root differs from the recorded string. Dedup
// must still key on the physical root and the leaf must not be treated as linked.
func TestHostCacheAliasedParentDoesNotOvercountSharedRoot(t *testing.T) {
	real := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skip(err)
	}
	hostWrite(t, filepath.Join(real, "pkgs", "a-1-0.conda"), "a")
	prefix := hostPrefix(t)
	writeMeta(t, prefix, "one.json", hostRecordJSON("one", fmt.Sprintf(`,"package_tarball_full_path":%q`, filepath.Join(alias, "pkgs", "a-1-0.conda"))))
	writeMeta(t, prefix, "two.json", hostRecordJSON("two", fmt.Sprintf(`,"package_tarball_full_path":%q`, filepath.Join(real, "pkgs", "a-1-0.conda"))))
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil {
		t.Fatal(err)
	}
	target := snapshot.Targets[0]
	if target.Coverage["host-cache"] != Complete || len(target.Archives) != 1 {
		t.Fatalf("aliased and direct spellings of one root overcounted: coverage=%q archives=%+v", target.Coverage["host-cache"], target.Archives)
	}
}
