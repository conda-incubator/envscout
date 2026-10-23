package evidence

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/testimage"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func loadEvidenceImage(t *testing.T, layers ...[]testimage.Entry) *imageinput.Loaded {
	t.Helper()
	loaded, err := imageinput.Load(context.Background(), testimage.Archive(t, layers...), "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loaded.Close(); err != nil {
			t.Error(err)
		}
	})
	return loaded
}

func packageMarker(p, name string) testimage.Entry {
	return testimage.Entry{Name: p, Data: fmt.Sprintf(`{"name":%q,"version":"1.0"}`, name)}
}
func commandEntry(p string) testimage.Entry {
	return testimage.Entry{Name: p, Data: "\x7fELFfixture", Mode: 0o755}
}
func collectFixture(t *testing.T, loaded *imageinput.Loaded, caps ...string) Target {
	t.Helper()
	target, err := CollectImage(context.Background(), loaded, Request{Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestImageLayouts(t *testing.T) {
	t.Setenv("CONDA_PREFIX", "/host-only-prefix")
	t.Setenv("MAMBA_ROOT_PREFIX", "/host-only-mamba")
	cases := []struct {
		name                                 string
		entries                              []testimage.Entry
		prefixes, archives, extracted, tools int
		tooling                              bool
	}{
		{"app-only", []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")}, 1, 0, 0, 0, false},
		{"app-in-base", []testimage.Entry{packageMarker("opt/base/conda-meta/python.json", "python")}, 1, 0, 0, 0, false},
		{"base-app-cache", []testimage.Entry{packageMarker("opt/conda/conda-meta/not-a-tool-name.json", "conda"), packageMarker("opt/conda/envs/app/conda-meta/python.json", "python"), {Name: "opt/conda/pkgs/python.conda", Data: "not parsed"}, packageMarker("opt/conda/pkgs/python-1.0/info/index.json", "python"), commandEntry("usr/bin/apt")}, 2, 1, 1, 1, true},
		{"cache-fake", []testimage.Entry{packageMarker("app/conda-meta/python.json", "python"), {Name: "tmp/pkgs/python.conda", Data: "fake"}, {Name: "opt/base/bin/conda", Data: "fake"}, {Name: "tmp/pkgs/site-packages/info/index.json", Data: "{}"}}, 1, 0, 0, 0, false},
		{"metadata-only", []testimage.Entry{{Name: "var/lib/dpkg/status", Data: "Package: apt"}, {Name: "var/lib/rpm/rpmdb.sqlite", Data: "rpm database"}, {Name: "usr/bin/apt", Data: "not executable"}, {Name: "usr/bin/yum", Data: "not a header", Mode: 0o755}}, 0, 0, 0, 0, false},
		{"custom-marker-cache", []testimage.Entry{packageMarker("downloads/package/info/index.json", "python"), {Name: "downloads/package.conda", Data: "archive"}}, 0, 1, 1, 0, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			loaded := loadEvidenceImage(t, test.entries)
			target := collectFixture(t, loaded, "prefixes", "tooling-prefix", "final-cache", "os-package-tools")
			if len(target.Prefixes) != test.prefixes || len(target.Archives) != test.archives || len(target.Extracted) != test.extracted || len(target.Tools) != test.tools {
				t.Fatalf("unexpected evidence: %+v", target)
			}
			tooling := false
			for _, prefix := range target.Prefixes {
				tooling = tooling || prefix.Tooling
			}
			if tooling != test.tooling {
				t.Fatalf("tooling = %v", tooling)
			}
			if target.ID != "oci:"+loaded.Identity.ManifestDigest+"@linux/amd64" || target.Input != loaded.Identity.Input || !reflect.DeepEqual(target.Image, &loaded.Identity) {
				t.Fatalf("identity = %+v", target)
			}
		})
	}
}

func TestImageOnlyRequestedCapabilities(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python"), {Name: "app/conda-meta/history", Data: "not valid history"}, commandEntry("usr/bin/apt")}, []testimage.Entry{{Name: "tmp/.wh.absent"}})
	target := collectFixture(t, loaded)
	data, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), ":null") {
		t.Fatalf("nil arrays: %s", data)
	}
	for cap, coverage := range target.Coverage {
		if coverage != NotCollected {
			t.Fatalf("%s: %s", cap, coverage)
		}
	}
	if len(target.Prefixes)+len(target.Tools)+len(target.Issues) != 0 {
		t.Fatalf("unrequested data: %+v", target)
	}
	target = collectFixture(t, loaded, "os-package-tools")
	if len(target.Tools) != 1 || len(target.Prefixes) != 0 || target.Coverage["prefixes"] != NotCollected || target.Coverage["layer-retention"] != NotCollected {
		t.Fatalf("capability isolation: %+v", target)
	}
	reader, err := loaded.Image.OpenPathFromSquash("/usr/bin/apt")
	if err != nil {
		t.Fatalf("collector cleaned image: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

type historyReadGuard struct {
	image.FileCatalogReader
	reads int
}

func (catalog *historyReadGuard) Open(ref file.Reference) (io.ReadCloser, error) {
	if strings.HasSuffix(string(ref.RealPath), "/conda-meta/history") {
		catalog.reads++
		return nil, errors.New("history must not be read")
	}
	return catalog.FileCatalogReader.Open(ref)
}

func TestImageUnrequestedHistoryIsNotRead(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python"), {Name: "app/conda-meta/history", Data: "==> 2026-01-01 <==\n"}})
	guard := &historyReadGuard{FileCatalogReader: loaded.Image.FileCatalog}
	loaded.Image.FileCatalog = guard
	target := collectFixture(t, loaded, "prefixes", "tooling-prefix", "runtime-config")
	if guard.reads != 0 || target.Coverage["prefixes"] != Complete || len(target.Prefixes) != 1 || target.Prefixes[0].Revision != nil {
		t.Fatalf("unrequested history reads=%d target=%+v", guard.reads, target)
	}
	target = collectFixture(t, loaded, "prefixes", "history")
	if guard.reads != 1 || target.Coverage["history"] != Partial || target.Coverage["prefixes"] != Complete {
		t.Fatalf("requested history reads=%d target=%+v", guard.reads, target)
	}
}

func TestImageToolEvidenceAndAliases(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{commandEntry("usr/bin/apt"), {Name: "usr/bin/apt-get", Type: tar.TypeSymlink, Link: "apt"}, {Name: "bin", Type: tar.TypeSymlink, Link: "usr/bin"}, {Name: "usr/bin/dnf", Data: "#!/usr/bin/python3\n", Mode: 0o755}, commandEntry("usr/bin/busybox"), {Name: "usr/bin/sh", Type: tar.TypeSymlink, Link: "busybox"}, {Name: "usr/bin/bash", Type: tar.TypeSymlink, Link: "busybox"}, {Name: "usr/sbin/rpm", Type: tar.TypeSymlink, Link: "/not-in-image/rpm"}, {Name: "usr/bin/dpkg", Data: "#!/bin/sh\n", Mode: 0o644}, {Name: "usr/bin/yum", Data: "ELF", Mode: 0o755}})
	target := collectFixture(t, loaded, "os-package-tools", "shell-tools")
	if len(target.Tools) != 2 || len(target.Shells) != 1 {
		t.Fatalf("tools = %+v shells = %+v", target.Tools, target.Shells)
	}
	if target.Coverage["os-package-tools"] != Partial || target.Coverage["shell-tools"] != Complete {
		t.Fatalf("coverage = %+v issues=%+v", target.Coverage, target.Issues)
	}
	if target.Tools[0].Reference == "" || target.Shells[0].Kind != "sh" {
		t.Fatalf("missing executable reference: %+v", target)
	}
}

func TestImageCacheLinks(t *testing.T) {
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			link := "/cache/python/lib/python.so"
			if kind == tar.TypeLink {
				link = "cache/python/lib/python.so"
			}
			loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/python/info/index.json", "python"), {Name: "cache/python/lib/python.so", Data: "runtime"}, packageMarker("app/conda-meta/python.json", "python"), {Name: "app/lib/python.so", Type: kind, Link: link}})
			target := collectFixture(t, loaded, "final-cache", "cache-link-dependencies")
			linked, coverage := kind == tar.TypeSymlink, Complete
			if kind == tar.TypeLink {
				coverage = Partial
			}
			if target.CacheLinked != linked || len(target.Extracted) != 1 || target.Coverage["cache-link-dependencies"] != coverage {
				t.Fatalf("link evidence = %+v", target)
			}
		})
	}
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/python/info/index.json", "python"), {Name: "cache/python/lib/python.so", Data: "runtime"}, {Name: "app/lib", Type: tar.TypeSymlink, Link: "/cache/python/lib"}})
	if target := collectFixture(t, loaded, "cache-link-dependencies"); !target.CacheLinked {
		t.Fatalf("directory link omitted: %+v", target)
	}
}

func TestImageRuntimeConfiguration(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), packageMarker("opt/conda/envs/app/conda-meta/python.json", "python"), commandEntry("opt/conda/bin/conda"), commandEntry("opt/conda/envs/app/bin/python")})
	loaded.Config.Config.Entrypoint = []string{"/opt/conda/envs/app/bin/python"}
	target := collectFixture(t, loaded, "runtime-config")
	if target.RuntimePrefix != "/opt/conda/envs/app" || target.RuntimeUsesTooling || len(target.Prefixes) != 0 {
		t.Fatalf("runtime = %+v", target)
	}
	loaded.Config.Config.Entrypoint = []string{"conda", "run"}
	loaded.Config.Config.Env = []string{"PATH=/opt/conda/bin"}
	target = collectFixture(t, loaded, "runtime-config")
	if !target.RuntimeUsesTooling {
		t.Fatalf("tool invocation = %+v", target)
	}
	loaded.Config.Config.Entrypoint = []string{"/wrapper"}
	loaded.Config.Config.Cmd = []string{"/opt/conda/envs/app/bin/python"}
	target = collectFixture(t, loaded, "runtime-config")
	if target.RuntimePrefix != "" || target.RuntimeUsesTooling {
		t.Fatalf("Cmd arguments used as executable hint = %+v", target)
	}
	loaded.Config.Config.Entrypoint = nil
	target = collectFixture(t, loaded, "runtime-config")
	if target.RuntimePrefix != "/opt/conda/envs/app" {
		t.Fatalf("Cmd executable hint=%+v", target)
	}
	_, err := CollectImage(context.Background(), loaded, Request{Capabilities: []string{"runtime-config"}, RuntimePrefix: "/no-such-prefix"})
	if err == nil {
		t.Fatal("invalid asserted prefix accepted")
	}
	target, err = CollectImage(context.Background(), loaded, Request{Capabilities: []string{"runtime-config"}, RuntimePrefix: "/opt/conda/envs/app"})
	if err != nil || target.RuntimePrefix != "/opt/conda/envs/app" {
		t.Fatalf("assertion = %+v %v", target, err)
	}
	loaded.Config = nil
	target = collectFixture(t, loaded, "runtime-config", "os-package-tools")
	if target.Coverage["runtime-config"] != Partial || target.Coverage["os-package-tools"] != Complete {
		t.Fatalf("independent coverage = %+v", target)
	}
}

func TestImageLayerOpaqueAndPartialPackage(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/lib/python.so", Data: "old runtime"}, {Name: "cache/pkg.conda", Data: "old archive"}}, []testimage.Entry{{Name: "cache/.wh..wh..opq"}})
	target := collectFixture(t, loaded, "layer-retention")
	if len(target.Retained) != 2 {
		t.Fatalf("opaque whiteout = %+v", target)
	}
	loaded = loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/lib/python.so", Data: "old runtime"}}, []testimage.Entry{{Name: "cache/pkg/lib/python.so", Data: "new runtime"}})
	target = collectFixture(t, loaded, "layer-retention")
	if len(target.Retained) != 1 || target.Retained[0].Kind != "extracted-overwritten" || target.Retained[0].Bytes != int64(len("old runtime")) {
		t.Fatalf("partially overwritten package = %+v", target)
	}
}

func TestImageHardlinkIdentityAcrossOverwrites(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/lib/python.so", Data: "old runtime"}, {Name: "app/python.so", Type: tar.TypeLink, Link: "cache/pkg/lib/python.so"}}, []testimage.Entry{{Name: "cache/pkg/lib/python.so", Data: "different runtime"}, {Name: "cache/pkg/info/.wh.index.json"}})
	target := collectFixture(t, loaded, "layer-retention", "cache-link-dependencies")
	if len(target.Retained) != 0 {
		t.Fatalf("surviving hardlink classified unused: %+v", target)
	}
	if target.Coverage["layer-retention"] != Partial || target.Coverage["cache-link-dependencies"] != Complete {
		t.Fatalf("unverified adopted identity: %+v", target)
	}
	loaded = loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/lib/python.so", Data: "old runtime"}, {Name: "app/python.so", Type: tar.TypeLink, Link: "cache/pkg/lib/python.so"}}, []testimage.Entry{{Name: "app/python.so", Data: "new runtime"}})
	target = collectFixture(t, loaded, "cache-link-dependencies")
	if target.CacheLinked {
		t.Fatalf("overwritten link remains dependency: %+v", target)
	}
}

func TestImageStableReferenceIdentity(t *testing.T) {
	entries := []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), {Name: "opt/conda/pkgs/pkg.conda", Data: "archive"}, commandEntry("usr/bin/apt")}
	first, second := loadEvidenceImage(t, entries), loadEvidenceImage(t, entries)
	a, b := collectFixture(t, first, "final-cache", "os-package-tools"), collectFixture(t, second, "final-cache", "os-package-tools")
	if a.ID != b.ID || !reflect.DeepEqual(a.Archives, b.Archives) || !reflect.DeepEqual(a.Tools, b.Tools) {
		t.Fatalf("unstable references: %+v %+v", a, b)
	}
}

func TestImagePositiveLayersSurvivePartialCoverage(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), {Name: "opt/conda/pkgs/pkg.conda", Data: "archive"}}, []testimage.Entry{{Name: "opt/conda/pkgs/.wh.pkg.conda"}, {Name: "unrelated", Type: tar.TypeSymlink, Link: "/missing"}})
	target := collectFixture(t, loaded, "layer-retention")
	if target.Coverage["layer-retention"] != Complete || len(target.Retained) != 1 {
		t.Fatalf("partial discarded positive evidence: %+v", target)
	}
}

func TestImageCacheDirectoryAliasChains(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			entries := []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/lib/data", Data: "runtime"}, {Name: "cache/alias", Type: tar.TypeSymlink, Link: "pkg/lib"}, {Name: "app/lib", Type: tar.TypeSymlink, Link: "/cache/alias"}, {Name: "unrelated", Type: tar.TypeSymlink, Link: "unrelated"}}
			if explicit {
				entries = append([]testimage.Entry{{Name: "cache/pkg/lib", Type: tar.TypeDir}}, entries...)
			}
			loaded := loadEvidenceImage(t, entries)
			target := collectFixture(t, loaded, "cache-link-dependencies")
			if !target.CacheLinked || target.Coverage["cache-link-dependencies"] != Complete {
				t.Fatalf("directory chain linkage=%+v", target)
			}
		})
	}
}

func TestImageLayerCacheContextsAreAsOfLayer(t *testing.T) {
	cases := []struct {
		name     string
		layers   [][]testimage.Entry
		retained int
	}{
		{"not-retroactive", [][]testimage.Entry{{{Name: "downloads/user.conda", Data: "unrelated archive"}}, {{Name: "downloads/.wh.user.conda"}, packageMarker("downloads/pkg/info/index.json", "python")}}, 0},
		{"removed-marker", [][]testimage.Entry{{packageMarker("cache/pkg/info/index.json", "python")}, {{Name: "cache/pkg/info/.wh.index.json"}}, {{Name: "cache/new.conda", Data: "not proven cache"}}, {{Name: "cache/.wh.new.conda"}}}, 1},
		{"replaced-marker", [][]testimage.Entry{{packageMarker("cache/pkg/info/index.json", "python")}, {{Name: "cache/pkg/info/index.json", Data: "{}"}}, {{Name: "cache/new.conda", Data: "not proven cache"}}, {{Name: "cache/.wh.new.conda"}}}, 1},
		{"removed-tooling", [][]testimage.Entry{{packageMarker("opt/conda/conda-meta/conda.json", "conda")}, {{Name: "opt/conda/conda-meta/.wh.conda.json"}}, {{Name: "opt/conda/pkgs/new.conda", Data: "not proven cache"}}, {{Name: "opt/conda/pkgs/.wh.new.conda"}}}, 0},
		{"surviving-marker", [][]testimage.Entry{{packageMarker("cache/pkg/info/index.json", "python")}, {{Name: "cache/new.conda", Data: "real cache"}}, {{Name: "cache/.wh.new.conda"}}}, 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			loaded := loadEvidenceImage(t, test.layers...)
			target := collectFixture(t, loaded, "layer-retention")
			if len(target.Retained) != test.retained {
				t.Fatalf("layer-relative cache context=%+v", target)
			}
			for _, artifact := range target.Retained {
				if strings.HasSuffix(artifact.Path, "new.conda") && test.name != "surviving-marker" {
					t.Fatalf("stale marker confirmed new archive=%+v", artifact)
				}
			}
		})
	}
}

func TestImageRuntimeCommandSemanticsAndPrivacy(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{commandEntry("usr/bin/python"), {Name: "loop", Type: tar.TypeSymlink, Link: "loop"}})
	loaded.Config.Config.Entrypoint = []string{"/usr/bin/python"}
	loaded.Config.Config.Cmd = []string{"PRIVATE_TOKEN"}
	loaded.Config.Config.Env = []string{"PATH=/loop"}
	target := collectFixture(t, loaded, "runtime-config")
	data, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE_TOKEN") || target.Coverage["runtime-config"] != Complete {
		t.Fatalf("argument privacy=%s", data)
	}
	for _, command := range []string{"PRIVATE_COMMAND", "/loop/PRIVATE_PATH"} {
		loaded.Config.Config.Entrypoint = []string{command}
		target = collectFixture(t, loaded, "runtime-config")
		data, err = json.Marshal(target)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "PRIVATE_") || target.Coverage["runtime-config"] != Partial {
			t.Fatalf("startup issue privacy=%s", data)
		}
		for _, issue := range target.Issues {
			if issue.Capability == "runtime-config" && issue.Path != "image startup" {
				t.Fatalf("untrusted command copied to issue=%+v", issue)
			}
		}
	}
}

func TestImageRuntimePrefixFromValidatedPATH(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("tools/conda-meta/conda.json", "conda"), packageMarker("app/conda-meta/python.json", "python"), commandEntry("app/bin/python")})
	loaded.Config.Config.Entrypoint = []string{"python"}
	loaded.Config.Config.Env = []string{"PATH=/app/bin"}
	target := collectFixture(t, loaded, "prefixes", "tooling-prefix", "runtime-config")
	if target.RuntimePrefix != "/app" || target.RuntimeUsesTooling || target.Coverage["runtime-config"] != Complete {
		t.Fatalf("PATH runtime hint=%+v", target)
	}
}

func TestImageDanglingCacheOnlyLinksDoNotImplyRuntimeDependency(t *testing.T) {
	for _, outside := range []bool{false, true} {
		t.Run(fmt.Sprint(outside), func(t *testing.T) {
			entries := []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/compiler_compat/ld", Type: tar.TypeSymlink, Link: "/missing-compiler"}, {Name: "cache/pkg/lib/libz.so", Type: tar.TypeSymlink, Link: "missing.so"}, {Name: "cache/alias", Type: tar.TypeSymlink, Link: "pkg/lib"}}
			if outside {
				entries = append(entries, testimage.Entry{Name: "app/libz.so", Type: tar.TypeSymlink, Link: "/cache/alias/libz.so"})
			}
			loaded := loadEvidenceImage(t, entries)
			target := collectFixture(t, loaded, "final-cache", "cache-link-dependencies", "layer-retention")
			want := Complete
			if outside {
				want = Partial
			}
			if target.Coverage["cache-link-dependencies"] != want || target.Coverage["layer-retention"] != want {
				t.Fatalf("dangling cache scope outside=%v target=%+v", outside, target)
			}
		})
	}
}

func TestImageOverwrittenHardlinkIntermediateRemainsUnknown(t *testing.T) {
	first := []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/data", Data: "old"}, {Name: "app/intermediate", Type: tar.TypeLink, Link: "cache/pkg/data"}, {Name: "app/live", Type: tar.TypeLink, Link: "app/intermediate"}, {Name: "app/intermediate", Data: "new"}}
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprint(removed), func(t *testing.T) {
			layers := [][]testimage.Entry{first}
			if removed {
				layers = append(layers, []testimage.Entry{{Name: "cache/.wh.pkg"}})
			}
			loaded := loadEvidenceImage(t, layers...)
			target := collectFixture(t, loaded, "cache-link-dependencies", "layer-retention")
			if target.Coverage["layer-retention"] != Partial || !removed && target.Coverage["cache-link-dependencies"] != Partial || len(target.Retained) != 0 {
				t.Fatalf("lost intermediate binding=%+v", target)
			}
		})
	}
}

func TestImageUnrelatedHardlinksAndPositiveRetention(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{commandEntry("usr/bin/perl"), {Name: "usr/bin/perl-alias", Type: tar.TypeLink, Link: "usr/bin/perl"}}, []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), {Name: "opt/conda/pkgs/archive.conda", Data: "archive"}}, []testimage.Entry{{Name: "opt/conda/pkgs/.wh.archive.conda"}})
	target := collectFixture(t, loaded, "cache-link-dependencies", "layer-retention")
	if len(target.Retained) != 1 || target.Coverage["layer-retention"] != Complete || target.Coverage["cache-link-dependencies"] != Complete {
		t.Fatalf("unrelated hardlink poisoned cache coverage=%+v", target)
	}
	loaded = loadEvidenceImage(t, []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), {Name: "opt/conda/pkgs/archive.conda", Data: "archive"}, {Name: "opt/conda/pkgs/ambiguous", Data: "runtime"}, {Name: "app/runtime", Type: tar.TypeLink, Link: "opt/conda/pkgs/ambiguous"}, {Name: "opt/conda/pkgs/broken", Type: tar.TypeSymlink, Link: "missing"}}, []testimage.Entry{{Name: "opt/conda/pkgs/.wh.archive.conda"}})
	target = collectFixture(t, loaded, "cache-link-dependencies", "layer-retention")
	if len(target.Retained) != 1 || target.Coverage["layer-retention"] != Partial || target.Coverage["cache-link-dependencies"] != Partial {
		t.Fatalf("partial cache identity erased independent archive=%+v", target)
	}
}

func TestImageModeOnlyAndExecutableEvidence(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{commandEntry("usr/bin/apt"), {Name: "usr/bin/apt-get", Type: tar.TypeLink, Link: "usr/bin/apt", Mode: 0o755}, {Name: "usr/bin/dnf", Data: "#!/usr/bin/python3\n", Mode: 0o755}, {Name: "usr/bin/yum", Data: "#!not-absolute\n", Mode: 0o755}, {Name: "usr/bin/bash", Data: "#!/bin/sh\n", Mode: 0o644}})
	target := collectFixture(t, loaded, "os-package-tools", "shell-tools")
	if len(target.Tools) != 3 || len(target.Shells) != 0 || target.Coverage["os-package-tools"] != Partial {
		t.Fatalf("execution evidence = %+v", target)
	}
}

func TestImageCancellationDuringReadClosesReader(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")})
	ctx, cancel := context.WithCancel(context.Background())
	guard := &cancelEvidenceCatalog{FileCatalogReader: loaded.Image.FileCatalog, cancel: cancel}
	loaded.Image.FileCatalog = guard
	_, err := CollectImage(ctx, loaded, Request{Capabilities: []string{"prefixes"}})
	if !errors.Is(err, context.Canceled) || !guard.closed {
		t.Fatalf("cancel err=%v reader closed=%v", err, guard.closed)
	}
}

type cancelEvidenceCatalog struct {
	image.FileCatalogReader
	cancel context.CancelFunc
	closed bool
}

func (catalog *cancelEvidenceCatalog) Open(ref file.Reference) (io.ReadCloser, error) {
	reader, err := catalog.FileCatalogReader.Open(ref)
	if err != nil {
		return nil, err
	}
	return cancelEvidenceReader{ReadCloser: reader, catalog: catalog}, nil
}

type cancelEvidenceReader struct {
	io.ReadCloser
	catalog *cancelEvidenceCatalog
}

func (reader cancelEvidenceReader) Read(p []byte) (int, error) {
	reader.catalog.cancel()
	return reader.ReadCloser.Read(p)
}
func (reader cancelEvidenceReader) Close() error {
	reader.catalog.closed = true
	return reader.ReadCloser.Close()
}

func TestImageArtifactAndIssueLimits(t *testing.T) {
	c := imageCollector{target: Target{Archives: []Artifact{}, Coverage: map[string]string{"final-cache": Complete, "os-package-tools": Complete}, Issues: []Issue{}}, limited: map[string]bool{}}
	for i := 0; i < imageEntryLimit+1; i++ {
		c.add("final-cache", &c.target.Archives, Artifact{Path: fmt.Sprint(i), Kind: "archive"})
	}
	if len(c.target.Archives) != imageEntryLimit || c.target.Coverage["final-cache"] != Partial || len(c.target.Issues) != 1 {
		t.Fatalf("artifact cap = %+v", c.target.Coverage)
	}
	for i := 0; i < imageEntryLimit+1; i++ {
		c.issue("final-cache", "/bad", "bad metadata")
	}
	c.issue("os-package-tools", "/bad", "unreadable tool")
	if len(c.target.Issues) > imageEntryLimit {
		t.Fatalf("issue cap = %d", len(c.target.Issues))
	}
	found := false
	for _, issue := range c.target.Issues {
		found = found || issue.Capability == "os-package-tools"
	}
	if !found {
		t.Fatal("second capability issue disappeared at issue limit")
	}
}

func TestImageLayerOverwriteAndWhiteout(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprint(removed), func(t *testing.T) {
			second := []testimage.Entry{{Name: "opt/conda/pkgs/pkg.conda", Data: "new archive"}}
			if removed {
				second = []testimage.Entry{{Name: "opt/conda/pkgs/.wh.pkg.conda"}}
			}
			loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), {Name: "opt/conda/pkgs/pkg.conda", Data: "old archive"}}, second)
			target := collectFixture(t, loaded, "layer-retention")
			if len(target.Retained) != 1 {
				t.Fatalf("retained = %+v", target)
			}
			artifact := target.Retained[0]
			wantKind := "archive-overwritten"
			if removed {
				wantKind = "archive-hidden"
			}
			if artifact.Kind != wantKind || artifact.Layer != 0 || artifact.DiffID != loaded.Config.RootFS.DiffIDs[0].String() || artifact.BlobDigest != loaded.Manifest.Layers[0].Digest.String() || artifact.LayerBytes != loaded.Manifest.Layers[0].Size || artifact.Bytes != int64(len("old archive")) {
				t.Fatalf("layer identity = %+v", artifact)
			}
			if target.Coverage["final-cache"] != NotCollected {
				t.Fatal("layer collection enabled final-cache")
			}
		})
	}
}

func TestImageHistoricalCacheMarkersAndHardlinks(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprint(linked), func(t *testing.T) {
			first := []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python"), {Name: "cache/pkg/lib/python.so", Data: "runtime"}}
			if linked {
				first = append(first, testimage.Entry{Name: "app/python.so", Type: tar.TypeLink, Link: "cache/pkg/lib/python.so"})
			}
			loaded := loadEvidenceImage(t, first, []testimage.Entry{{Name: "cache/.wh.pkg"}})
			target := collectFixture(t, loaded, "layer-retention")
			if linked && len(target.Retained) != 0 || !linked && len(target.Retained) != 1 {
				t.Fatalf("linked=%v retained=%+v issues=%+v", linked, target.Retained, target.Issues)
			}
			if linked && target.Coverage["layer-retention"] != Partial {
				t.Fatalf("unverified hardlink coverage: %+v", target)
			}
		})
	}
	loaded := loadEvidenceImage(t, []testimage.Entry{{Name: "fake/pkgs/pkg.conda", Data: "archive"}}, []testimage.Entry{{Name: "fake/pkgs/.wh.pkg.conda"}})
	if target := collectFixture(t, loaded, "layer-retention"); len(target.Retained) != 0 {
		t.Fatalf("fake retained cache: %+v", target)
	}
}

func TestImageSameTarHardlinkOverwriteIsUnknown(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "python"),
		{Name: "cache/pkg/file", Data: "old"},
		{Name: "app/file", Type: tar.TypeLink, Link: "cache/pkg/file"},
		{Name: "cache/pkg/file", Data: "new"},
	})
	reader, err := loaded.Image.OpenPathFromSquash("/app/file")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(data) != "old" {
		t.Fatalf("adopter opener=%q read=%v close=%v", data, readErr, closeErr)
	}
	target := collectFixture(t, loaded, "cache-link-dependencies", "layer-retention")
	if target.CacheLinked || target.Coverage["cache-link-dependencies"] != Partial || target.Coverage["layer-retention"] != Partial {
		t.Fatalf("false shared identity: %+v", target)
	}
	loaded = loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "python"),
		{Name: "cache/pkg/file", Data: "old"},
		{Name: "app/file", Type: tar.TypeLink, Link: "cache/pkg/file"},
		{Name: "cache/pkg/file", Data: "new"},
		{Name: "cache/pkg/copy", Type: tar.TypeLink, Link: "app/file"},
	})
	target = collectFixture(t, loaded, "cache-link-dependencies")
	if target.CacheLinked || target.Coverage["cache-link-dependencies"] != Partial {
		t.Fatalf("unrecoverable inverse hardlink identity: %+v", target)
	}
	loaded = loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "python"),
		{Name: "cache/pkg/file", Data: "old"},
		{Name: "app/file", Type: tar.TypeLink, Link: "cache/pkg/file"},
		{Name: "cache/pkg/file", Data: "new"},
	}, []testimage.Entry{{Name: "cache/.wh.pkg"}})
	target = collectFixture(t, loaded, "layer-retention")
	if len(target.Retained) != 0 || target.Coverage["layer-retention"] != Partial {
		t.Fatalf("unproven hardlink unused guard: %+v", target)
	}
}

func TestImageLayerPackagePayloadAddedAfterMarker(t *testing.T) {
	for _, mode := range []string{"hidden", "overwritten", "hardlinked", "unconfirmed"} {
		t.Run(mode, func(t *testing.T) {
			first := []testimage.Entry{packageMarker("cache/pkg/info/index.json", "python")}
			if mode == "unconfirmed" {
				first = []testimage.Entry{{Name: "cache/unrelated", Data: "not a package marker"}}
			}
			second := []testimage.Entry{{Name: "cache/pkg/file", Data: "later payload"}}
			if mode == "hardlinked" {
				second = append(second, testimage.Entry{Name: "app/file", Type: tar.TypeLink, Link: "cache/pkg/file"})
			}
			third := []testimage.Entry{{Name: "cache/pkg/.wh.file"}}
			if mode == "overwritten" {
				third = []testimage.Entry{{Name: "cache/pkg/file", Data: "replacement"}}
			}
			loaded := loadEvidenceImage(t, first, second, third)
			target := collectFixture(t, loaded, "layer-retention")
			if mode == "hardlinked" {
				if len(target.Retained) != 0 || target.Coverage["layer-retention"] != Partial {
					t.Fatalf("unverified later hardlink=%+v", target)
				}
				return
			}
			if mode == "unconfirmed" {
				if len(target.Retained) != 0 {
					t.Fatalf("unconfirmed package=%+v", target)
				}
				return
			}
			if len(target.Retained) != 1 {
				t.Fatalf("later payload omitted: %+v", target)
			}
			artifact := target.Retained[0]
			if artifact.Layer != 1 || artifact.Kind != "extracted-"+mode || artifact.Bytes != int64(len("later payload")) || artifact.DiffID != loaded.Config.RootFS.DiffIDs[1].String() || artifact.BlobDigest != loaded.Manifest.Layers[1].Digest.String() || artifact.LayerBytes != loaded.Manifest.Layers[1].Size || !strings.HasSuffix(artifact.Reference, ":/cache/pkg/file") {
				t.Fatalf("payload source attribution=%+v", artifact)
			}
		})
	}
}

func TestImagePartialMetadataKeepsPositiveEvidence(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("opt/conda/conda-meta/conda.json", "conda"), {Name: "opt/conda/pkgs/pkg.conda", Data: "archive"}, {Name: "opt/conda/pkgs/broken/info/index.json", Data: strings.Repeat("x", imageMetadataLimit+1)}})
	target := collectFixture(t, loaded, "final-cache", "tooling-prefix", "os-package-tools")
	if len(target.Archives) != 1 || target.Coverage["final-cache"] != Partial || target.Coverage["tooling-prefix"] != Complete || target.Coverage["os-package-tools"] != Complete {
		t.Fatalf("partial positive = %+v", target)
	}
}

type limitEvidenceTree struct {
	filetree.Reader
	visits int
}

func (tree *limitEvidenceTree) Walk(fn func(file.Path, filenode.FileNode) error, conditions *filetree.WalkConditions) error {
	for i := 0; i < imagePathLimit+2; i++ {
		p := file.Path(fmt.Sprintf("/path-%d", i))
		node := filenode.FileNode{FileType: file.TypeDirectory}
		if conditions.ShouldTerminate(p, node) {
			return nil
		}
		tree.visits++
		if err := fn(p, node); err != nil {
			return err
		}
	}
	return nil
}

func TestImageTraversalCapsAndCancellation(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{{Name: "file", Data: "x"}})
	c := imageCollector{ctx: context.Background(), loaded: loaded, tree: loaded.Image.SquashedTree(), target: Target{Coverage: map[string]string{"layer-retention": Complete}, Issues: []Issue{}}, caches: map[string]bool{}, limited: map[string]bool{}}
	tree := &limitEvidenceTree{Reader: c.tree}
	visited := 0
	if err := c.walk(tree, []string{"layer-retention"}, &visited, func(file.Path, filenode.FileNode) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if visited != imagePathLimit || c.target.Coverage["layer-retention"] != Partial || len(c.target.Issues) != 1 {
		t.Fatalf("limit=%d %+v", visited, c.target)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectImage(ctx, loaded, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	if _, err := CollectImage(context.Background(), nil, Request{}); err == nil {
		t.Fatal("nil image accepted")
	}
	loaded.Manifest = nil
	loaded.Config = &v1.ConfigFile{}
	target := collectFixture(t, loaded, "layer-retention")
	if target.Coverage["layer-retention"] != Partial {
		t.Fatalf("missing descriptors=%+v", target)
	}
}
