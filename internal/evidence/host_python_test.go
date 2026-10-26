package evidence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func hostPythonIndex(t *testing.T, prefix string) (*hostFileResolver, *Target) {
	t.Helper()
	root, err := os.OpenRoot(prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	target := &Target{Coverage: map[string]string{"python-distributions": Complete}}
	r := &hostFileResolver{ctx: context.Background(), root: root, base: prefix, files: map[string]os.FileInfo{}}
	visited := 0
	for _, installation := range []string{filepath.Join("lib", "python3.12", "site-packages"), filepath.Join("Lib", "site-packages")} {
		if err := indexHostPython(context.Background(), root, installation, r, target, &visited); err != nil {
			t.Fatalf("indexHostPython(%s): %v", installation, err)
		}
	}
	sort.Strings(r.paths)
	return r, target
}

func indexedHas(r *hostFileResolver, name string) bool {
	return r.files[filepath.FromSlash(name)] != nil
}

func TestHostPythonIndexKeepsSyftMetadataAndSupportFilesOnly(t *testing.T) {
	prefix := t.TempDir()
	site := filepath.Join(prefix, "lib", "python3.12", "site-packages")
	for _, rel := range []string{
		"demo-1.dist-info/METADATA",
		"demo-1.dist-info/RECORD",
		"demo-1.dist-info/WHEEL",
		"demo-1.dist-info/INSTALLER",
		"demo-1.dist-info/direct_url.json",
		"demo-1.dist-info/top_level.txt",
		"demo-1.dist-info/LICENSE",
		"demo-1.dist-info/nested/deep/ignored.txt",
		"legacy-2.egg-info/PKG-INFO",
		"legacy-2.egg-info/installed-files.txt",
		"single-3.egg-info",
		"unrelated.txt",
		"app/static/big/data.bin",
	} {
		hostWrite(t, filepath.Join(site, filepath.FromSlash(rel)), "Name: x\nVersion: 1\n")
	}
	r, _ := hostPythonIndex(t, prefix)
	base := "lib/python3.12/site-packages/"
	for _, want := range []string{
		base + "demo-1.dist-info/METADATA",
		base + "demo-1.dist-info/RECORD",
		base + "demo-1.dist-info/direct_url.json",
		base + "demo-1.dist-info/top_level.txt",
		base + "demo-1.dist-info/LICENSE",
		base + "legacy-2.egg-info/PKG-INFO",
		base + "legacy-2.egg-info/installed-files.txt",
		base + "single-3.egg-info",
	} {
		if !indexedHas(r, want) {
			t.Errorf("missing indexed Syft-read path %q; indexed=%v", want, r.paths)
		}
	}
	for _, unwanted := range []string{
		base + "demo-1.dist-info/nested/deep/ignored.txt",
		base + "unrelated.txt",
		base + "app/static/big/data.bin",
	} {
		if indexedHas(r, unwanted) {
			t.Errorf("indexed application or unrelated path %q", unwanted)
		}
	}
}

func TestHostPythonIndexIgnoresApplicationTreesWithoutReadingThem(t *testing.T) {
	prefix := t.TempDir()
	site := filepath.Join(prefix, "lib", "python3.12", "site-packages")
	hostWrite(t, filepath.Join(site, "demo-1.dist-info/METADATA"), "Name: demo\nVersion: 1\n")
	// A large application tree must not be enumerated beyond its top-level
	// directory and must not contribute indexed files or visited counts.
	for i := 0; i < 2000; i++ {
		hostWrite(t, filepath.Join(site, "app", fmt.Sprintf("f%04d.py", i)), "x")
	}
	r, _ := hostPythonIndex(t, prefix)
	if len(r.paths) != 1 {
		t.Fatalf("application tree indexed: %d paths", len(r.paths))
	}
}

func TestHostPythonIndexLinkedDistributionEntriesArePartial(t *testing.T) {
	prefix := t.TempDir()
	site := filepath.Join(prefix, "lib", "python3.12", "site-packages")
	out := t.TempDir()
	hostWrite(t, filepath.Join(out, "METADATA"), "Name: out\nVersion: 1\n")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(site, "outside-1.dist-info")); err != nil {
		t.Skip(err)
	}
	r, target := hostPythonIndex(t, prefix)
	if target.Coverage["python-distributions"] != Partial {
		t.Fatalf("linked distribution entry not Partial: %q", target.Coverage["python-distributions"])
	}
	if len(r.paths) != 0 {
		t.Fatalf("linked entry was followed: %v", r.paths)
	}
}

func TestHostPythonNonRegularPrimaryMetadataIsIncomplete(t *testing.T) {
	prefix := hostPrefix(t)
	if err := os.MkdirAll(filepath.Join(prefix, "lib/python3.12/site-packages/demo-1.dist-info/METADATA"), 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || snapshot.Targets[0].Coverage["python-distributions"] != Partial || len(snapshot.Targets[0].Python) != 0 {
		t.Fatalf("non-regular primary metadata cannot establish a complete catalog: %+v %v", snapshot, err)
	}
}

func TestHostPythonIndexRespectsEntryCap(t *testing.T) {
	prefix := t.TempDir()
	site := filepath.Join(prefix, "lib", "python3.12", "site-packages")
	for i := 0; i < hostEntryLimit+5; i++ {
		hostWrite(t, filepath.Join(site, fmt.Sprintf("pkg%05d-1.dist-info", i), "METADATA"), "Name: p\nVersion: 1\n")
	}
	r, target := hostPythonIndex(t, prefix)
	if target.Coverage["python-distributions"] != Partial {
		t.Fatal("entry cap exceeded without Partial coverage")
	}
	if len(r.paths) > hostEntryLimit {
		t.Fatalf("indexed %d paths, cap %d", len(r.paths), hostEntryLimit)
	}
}

func BenchmarkHostPythonIndexApplicationHeavy(b *testing.B) {
	prefix := b.TempDir()
	site := filepath.Join(prefix, "lib", "python3.12", "site-packages")
	for i := 0; i < 25000; i++ {
		_ = os.MkdirAll(filepath.Join(site, "app", fmt.Sprint(i%50)), 0o755)
		_ = os.WriteFile(filepath.Join(site, "app", fmt.Sprint(i%50), fmt.Sprintf("f%05d.py", i)), []byte("x"), 0o644)
	}
	_ = os.MkdirAll(filepath.Join(site, "demo-1.dist-info"), 0o755)
	_ = os.WriteFile(filepath.Join(site, "demo-1.dist-info", "METADATA"), []byte("Name: demo\nVersion: 1\n"), 0o644)
	root, err := os.OpenRoot(prefix)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		r := &hostFileResolver{ctx: context.Background(), root: root, base: prefix, files: map[string]os.FileInfo{}}
		target := &Target{Coverage: map[string]string{}}
		visited := 0
		if err := indexHostPython(context.Background(), root, filepath.Join("lib", "python3.12", "site-packages"), r, target, &visited); err != nil {
			b.Fatal(err)
		}
	}
}
