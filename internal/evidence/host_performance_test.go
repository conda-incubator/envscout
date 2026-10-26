package evidence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostPythonIgnoresApplicationPayloadTrees(t *testing.T) {
	prefix := hostPrefix(t)
	installation := filepath.Join(prefix, "lib/python3.12/site-packages")
	hostWrite(t, filepath.Join(installation, "demo-1.dist-info/METADATA"), "Name: demo\nVersion: 1\n")
	hostWrite(t, filepath.Join(installation, "application/tests/fixture-1.dist-info/METADATA"), "Name: fixture\nVersion: 1\n")
	// Even an application payload deeper than the evidence walk budget is not
	// installed distribution metadata and must neither be visited nor cataloged.
	deep := filepath.Join(installation, "application", strings.Repeat("d/", 130), "payload.py")
	hostWrite(t, deep, "payload")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"python-distributions"}})
	if err != nil || len(snapshot.Targets[0].Python) != 1 || snapshot.Targets[0].Python[0].Name != "demo" || snapshot.Targets[0].Coverage["python-distributions"] != Complete {
		t.Fatalf("application payload should not affect installed metadata coverage: %+v %v", snapshot, err)
	}
}

func TestHostCacheDoesNotTraverseExtractedPayload(t *testing.T) {
	prefix := hostPrefix(t)
	cache := t.TempDir()
	packageDir := filepath.Join(cache, "demo-1-0")
	writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", fmt.Sprintf(`,"extracted_package_dir":%q`, packageDir)))
	hostWrite(t, filepath.Join(packageDir, "info/index.json"), `{"name":"demo","version":"1","build":"0","build_number":0}`)
	hostWrite(t, filepath.Join(packageDir, strings.Repeat("d/", 130), "payload"), "not needed for cache presence")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || snapshot.Targets[0].Coverage["host-cache"] != Complete || len(snapshot.Targets[0].Extracted) != 1 || snapshot.Targets[0].Extracted[0].Bytes != 0 {
		t.Fatalf("only the extracted marker is needed, not a recursive byte census: %+v %v", snapshot, err)
	}
}

func TestHostCacheFactsAreSharedOnlyWithinCollection(t *testing.T) {
	cache := t.TempDir()
	hostWrite(t, filepath.Join(cache, "demo-1-0.conda"), "archive")
	root := t.TempDir()
	for _, env := range []string{"a", "b"} {
		prefix := filepath.Join(root, env)
		writeMeta(t, prefix, "pkg.json", hostRecordJSON("demo", fmt.Sprintf(`,"package_tarball_full_path":%q`, filepath.Join(cache, "demo-1-0.conda"))))
	}
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || len(snapshot.Targets) != 2 {
		t.Fatalf("expected two prefixes sharing a cache: %+v %v", snapshot, err)
	}
	for _, target := range snapshot.Targets {
		if target.Coverage["host-cache"] != Complete || len(target.Archives) != 1 || target.Archives[0].Bytes != 7 {
			t.Fatalf("each prefix needs the same immutable cache facts: %+v", target)
		}
	}
	snapshot.Targets[0].Archives[0].Bytes = 99
	if snapshot.Targets[1].Archives[0].Bytes != 7 {
		t.Fatal("targets must not share mutable artifact slices")
	}
	hostWrite(t, filepath.Join(cache, "demo-1-0.conda"), "updated archive")
	snapshot, err = CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"host-cache"}})
	if err != nil || snapshot.Targets[0].Archives[0].Bytes != 15 {
		t.Fatalf("cache observations must not persist between runs: %+v %v", snapshot, err)
	}
}

func BenchmarkHostCacheDeepPayload(b *testing.B) {
	cache := b.TempDir()
	for i := range 40 {
		dir := filepath.Join(cache, fmt.Sprintf("pkg%d-1-0", i))
		name := filepath.Join(dir, "info/index.json")
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(fmt.Sprintf(`{"name":"pkg%d","version":"1","build":"0","build_number":0}`, i)), 0o644); err != nil {
			b.Fatal(err)
		}
		for j := range 200 {
			name = filepath.Join(dir, "a/b/c/d/e/f/g", fmt.Sprintf("file%d", j))
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(name, []byte("payload"), 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ResetTimer()
	for b.Loop() {
		visited := 0
		target := Target{Coverage: map[string]string{"host-cache": Complete}}
		scanHostCache(context.Background(), &target, cache, &visited)
		if target.Coverage["host-cache"] != Complete || len(target.Extracted) != 40 || visited != 40 {
			b.Fatalf("all cache entries must be found without entering payloads: %+v, visited=%d", target, visited)
		}
	}
}
