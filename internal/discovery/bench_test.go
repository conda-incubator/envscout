package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// buildSyntheticTree creates thousands of ordinary directories, several pruned trees
// (.git, node_modules, site-packages) that the walk must skip, and a few real prefixes.
func buildSyntheticTree(b *testing.B, dirs int) string {
	b.Helper()
	root := b.TempDir()
	for i := 0; i < dirs; i++ {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("d%03d", i%50), fmt.Sprintf("s%04d", i)), 0o755); err != nil {
			b.Fatal(err)
		}
	}
	for _, pruned := range []string{".git", "node_modules", "site-packages"} {
		for i := 0; i < 500; i++ {
			if err := os.MkdirAll(filepath.Join(root, pruned, fmt.Sprintf("p%04d", i)), 0o755); err != nil {
				b.Fatal(err)
			}
		}
	}
	for i := 0; i < 5; i++ {
		prefix := filepath.Join(root, "envs", fmt.Sprintf("env%d", i))
		if err := os.MkdirAll(filepath.Join(prefix, "conda-meta"), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(prefix, "conda-meta", "pkg.json"), []byte(imagePackageJSON), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	return root
}

// BenchmarkFindSyntheticHost walks a synthetic tree with the production pruning rules.
// Fastwalk worker count is the library default; see the comment in walkRoot.
func BenchmarkFindSyntheticHost(b *testing.B) {
	root := buildSyntheticTree(b, 5000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := Find(context.Background(), []string{root}, false)
		if err != nil || len(report.Environments) != 5 {
			b.Fatalf("environments=%d err=%v", len(report.Environments), err)
		}
	}
}

// BenchmarkFindKnown probes an isolated temp home with a container of prefixes. The
// inputs are injected, so no host environment or real home directory is read.
func BenchmarkFindKnown(b *testing.B) {
	home := b.TempDir()
	container := filepath.Join(home, ".conda", "envs")
	for i := 0; i < 200; i++ {
		prefix := filepath.Join(container, fmt.Sprintf("env%03d", i))
		if err := os.MkdirAll(filepath.Join(prefix, "conda-meta"), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(prefix, "conda-meta", "pkg.json"), []byte(imagePackageJSON), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	inputs := knownInputs{home: home, goos: "darwin", env: map[string]string{}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report, err := findKnown(context.Background(), inputs)
		if err != nil || len(report.Environments) != 200 {
			b.Fatalf("environments=%d err=%v", len(report.Environments), err)
		}
	}
}
